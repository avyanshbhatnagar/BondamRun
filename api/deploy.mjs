#!/usr/bin/env node
/**
 * Bondam Run - one-command deploy to Cloudflare (free plan friendly).
 *
 *   node deploy.mjs            deploy (safe to re-run any time)
 *   node deploy.mjs --dry-run  check config + talk to the API read-only, skip wrangler
 *
 * It will, in order:
 *   1. verify your API token
 *   2. create the D1 database if it does not exist
 *   3. make sure your account has a workers.dev subdomain (creates one if WORKERS_SUBDOMAIN is set)
 *   4. write worker/wrangler.toml
 *   5. apply SQL migrations to the remote D1 database
 *   6. deploy the Worker
 *   7. create the PEPPER and SESSION_SECRET secrets ONCE (never overwritten on re-deploys)
 *   8. smoke-test /api/health
 *
 * Needs Node 18+ and internet. Reads settings from environment variables or a `.env` file.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const WORKER_DIR = path.join(ROOT, 'worker');
const DRY = process.argv.includes('--dry-run');

/* ----------------------------------------------------------- config */
function loadDotEnv(file) {
  if (!existsSync(file)) return;
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}
loadDotEnv(path.join(ROOT, '.env'));

const cfg = {
  token: process.env.CLOUDFLARE_API_TOKEN,
  account: process.env.CLOUDFLARE_ACCOUNT_ID,
  origins: process.env.ALLOWED_ORIGINS,
  worker: process.env.WORKER_NAME || 'bondam-run-api',
  d1: process.env.D1_NAME || 'bondam-run-db',
  subdomain: process.env.WORKERS_SUBDOMAIN || '',
  api: process.env.CLOUDFLARE_API_BASE || 'https://api.cloudflare.com/client/v4',
};

const step = (n, msg) => console.log(`\n[${n}] ${msg}`);
const fail = (msg) => { console.error(`\n✖ ${msg}\n`); process.exit(1); };

function checkConfig() {
  const missing = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'ALLOWED_ORIGINS'].filter((k) => !process.env[k]);
  if (missing.length) fail(`Missing ${missing.join(', ')}. Copy .env.example to .env and fill it in.`);
  if (!/^[a-z0-9-]{3,63}$/.test(cfg.worker)) fail('WORKER_NAME may only contain lower-case letters, digits and dashes.');
  const list = cfg.origins.split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
  for (const o of list) {
    let u; try { u = new URL(o); } catch { fail(`ALLOWED_ORIGINS entry "${o}" is not a URL.`); }
    if (u.pathname !== '/' || u.search || u.hash) fail(`"${o}" must be just the origin (no path). For GitHub Pages use https://<your-github-username>.github.io`);
  }
  cfg.origins = list.join(',');
}

/* ----------------------------------------------------------- Cloudflare REST */
async function cf(method, pathname, body) {
  const res = await fetch(cfg.api + pathname, {
    method,
    headers: { Authorization: `Bearer ${cfg.token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok || !json || json.success === false) {
    const errs = json && json.errors ? json.errors.map((e) => `${e.code}: ${e.message}`).join('; ') : `HTTP ${res.status}`;
    const e = new Error(errs); e.status = res.status; e.errors = json && json.errors; throw e;
  }
  return json.result;
}

async function verifyToken() {
  for (const p of [`/accounts/${cfg.account}/tokens/verify`, '/user/tokens/verify']) {
    try {
      const r = await cf('GET', p);
      if (r.status === 'active') return;
      fail(`Token status is "${r.status}". Create a new one (see README).`);
    } catch (e) { if (p.startsWith('/user')) fail(`Cloudflare rejected the token: ${e.message}`); }
  }
}

async function ensureD1() {
  const list = await cf('GET', `/accounts/${cfg.account}/d1/database?name=${encodeURIComponent(cfg.d1)}&per_page=50`);
  const hit = (list || []).find((d) => d.name === cfg.d1);
  if (hit) { console.log(`   found D1 database "${cfg.d1}" (${hit.uuid})`); return hit.uuid; }
  const made = await cf('POST', `/accounts/${cfg.account}/d1/database`, { name: cfg.d1 });
  console.log(`   created D1 database "${cfg.d1}" (${made.uuid})`);
  return made.uuid;
}

async function ensureSubdomain() {
  try {
    const r = await cf('GET', `/accounts/${cfg.account}/workers/subdomain`);
    if (r && r.subdomain) { console.log(`   workers.dev subdomain: ${r.subdomain}`); return r.subdomain; }
  } catch { /* not set yet */ }
  if (!cfg.subdomain) fail('Your account has no workers.dev subdomain yet. Add WORKERS_SUBDOMAIN=<pick-a-unique-name> to .env and re-run.');
  const r = await cf('PUT', `/accounts/${cfg.account}/workers/subdomain`, { subdomain: cfg.subdomain });
  console.log(`   registered workers.dev subdomain: ${r.subdomain || cfg.subdomain}`);
  return r.subdomain || cfg.subdomain;
}

/* ----------------------------------------------------------- wrangler */
function wrangler(args, { input, allowFail } = {}) {
  if (DRY) { console.log(`   (dry-run) wrangler ${args.join(' ')}`); return { status: 0, stdout: '', stderr: '' }; }
  const win = process.platform === 'win32';
  const r = spawnSync(win ? 'npx.cmd' : 'npx', ['--yes', 'wrangler@4', ...args], {
    cwd: WORKER_DIR, input, encoding: 'utf8', shell: win,
    env: { ...process.env, CLOUDFLARE_API_TOKEN: cfg.token, CLOUDFLARE_ACCOUNT_ID: cfg.account, CI: 'true', WRANGLER_SEND_METRICS: 'false' },
  });
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.status !== 0 && !allowFail) fail(`wrangler ${args[0]} ${args[1] || ''} failed (exit ${r.status}).`);
  return r;
}

function renderWranglerToml(dbId) {
  const toml = `# Generated by deploy.mjs - do not edit by hand.
name = "${cfg.worker}"
main = "src/index.js"
compatibility_date = "2025-01-01"
account_id = "${cfg.account}"
workers_dev = true

[vars]
ALLOWED_ORIGINS = "${cfg.origins}"

[[d1_databases]]
binding = "DB"
database_name = "${cfg.d1}"
database_id = "${dbId}"
migrations_dir = "migrations"
`;
  writeFileSync(path.join(WORKER_DIR, 'wrangler.toml'), toml);
}

function ensureSecrets() {
  const wanted = ['PEPPER', 'SESSION_SECRET'];
  const localFile = path.join(ROOT, '.deploy-secrets.json');
  const local = existsSync(localFile) ? JSON.parse(readFileSync(localFile, 'utf8')) : {};
  const r = wrangler(['secret', 'list', '--format', 'json'], { allowFail: true });
  let existing = [];
  try { existing = JSON.parse(r.stdout || '[]').map((s) => s.name); } catch { /* none yet */ }

  const toUpload = {};
  for (const name of wanted) {
    if (existing.includes(name)) { console.log(`   ${name}: already set on Cloudflare - left untouched`); continue; }
    // Value order: environment (optional GitHub secret) > local backup file > freshly generated.
    if (process.env[name]) local[name] = process.env[name];
    if (!local[name]) local[name] = randomBytes(32).toString('hex');
    toUpload[name] = local[name];
    console.log(`   ${name}: will be created`);
  }
  if (Object.keys(toUpload).length) {
    writeFileSync(localFile, JSON.stringify(local, null, 2), { mode: 0o600 });
    const tmp = path.join(WORKER_DIR, '.secrets.upload.json');
    writeFileSync(tmp, JSON.stringify(toUpload), { mode: 0o600 });
    try { wrangler(['secret', 'bulk', '.secrets.upload.json']); } finally { try { unlinkSync(tmp); } catch { /* ignore */ } }
    if (process.env.GITHUB_ACTIONS) console.log(`   Created automatically and stored only on Cloudflare (nobody can read them back, including you).`);
    else console.log(`   A local copy is in .deploy-secrets.json. KEEP IT SAFE (and out of git):`);
    console.log(`   If PEPPER is ever deleted or replaced, every player has to reset their password.`);
  }
}

/* ----------------------------------------------------------- main */
(async () => {
  console.log(DRY ? 'Bondam Run deploy (dry run)' : 'Bondam Run deploy');
  checkConfig();

  step(1, 'Checking API token');
  await verifyToken();
  console.log('   token is active');

  step(2, 'D1 database');
  const dbId = await ensureD1();

  step(3, 'workers.dev subdomain');
  const sub = await ensureSubdomain();

  step(4, 'Writing worker/wrangler.toml');
  renderWranglerToml(dbId);

  step(5, 'Applying database migrations');
  wrangler(['d1', 'migrations', 'apply', cfg.d1, '--remote']);

  step(6, 'Deploying Worker');
  wrangler(['deploy']);

  step(7, 'Secrets');
  ensureSecrets();

  const url = `https://${cfg.worker}.${sub}.workers.dev`;
  step(8, `Smoke test ${url}/api/health`);
  if (DRY) console.log('   (dry-run) skipped');
  else {
    let ok = false;
    for (let i = 0; i < 6 && !ok; i++) {
      try { const r = await fetch(`${url}/api/health`); ok = r.ok; } catch { /* DNS may take a few seconds */ }
      if (!ok) await new Promise((r) => setTimeout(r, 3000));
    }
    console.log(ok ? '   ✔ API is up' : '   ⚠ not reachable yet - wait a minute and open the URL in a browser');
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    try {
      writeFileSync(process.env.GITHUB_STEP_SUMMARY, `## API deployed\n\nYour API address: \`${url}\`\n\nPut it in **config.js** in your game repo:\n\n\`\`\`js\nwindow.BONDAM_API = '${url}';\n\`\`\`\n`, { flag: 'a' });
    } catch { /* summary is optional */ }
  }
  console.log(`\n✔ Done.\n   API base URL (put this in the game): ${url}\n   Allowed web origins: ${cfg.origins}\n`);
})().catch((e) => fail(e.message || String(e)));
