/**
 * End-to-end tests against a LOCAL worker:
 *   terminal 1:  npm run dev:setup && npm run dev      (needs worker/.dev.vars, see .dev.vars.example)
 *   terminal 2:  npm test
 * It wipes the local dev database first (never touches Cloudflare).
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { hashPassword } from '../client/auth-client.js';

const BASE = process.env.BASE || 'http://localhost:8787';
const WORKER_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'worker');
const ORIGIN = 'http://localhost:8080';
let pass = 0, failed = 0;
const ok = (c, name, extra = '') => { c ? pass++ : failed++; console.log(`${c ? '  ✔' : '  ✖'} ${name}${c ? '' : '  ' + extra}`); };

const sql = (command) => spawnSync(process.platform === 'win32' ? 'npx.cmd' : 'npx',
  ['--yes', 'wrangler@4', 'd1', 'execute', 'bondam-run-db', '--local', '-c', 'wrangler.dev.toml', '--json', '--command', command],
  { cwd: WORKER_DIR, encoding: 'utf8', shell: process.platform === 'win32' });

async function api(p, { method = 'GET', body, token, origin = ORIGIN } = {}) {
  const res = await fetch(BASE + p, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(origin ? { Origin: origin } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, headers: res.headers, json: await res.json().catch(() => ({})) };
}
const creds = async (u, p) => ({ username: u, pw: await hashPassword(u, p) });

console.log('Resetting local database');
sql('DELETE FROM throttle; DELETE FROM users;');

console.log('\nHealth & CORS');
let r = await api('/api/health');
ok(r.status === 200 && r.json.ok, 'health ok');
ok(r.headers.get('access-control-allow-origin') === ORIGIN, 'allowed origin is echoed back');
r = await api('/api/health', { origin: 'https://evil.example' });
ok(!r.headers.get('access-control-allow-origin'), 'other origins get no CORS header');
const pre = await fetch(BASE + '/api/login', { method: 'OPTIONS', headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'POST' } });
ok(pre.status === 204 && pre.headers.get('access-control-allow-headers').includes('Authorization'), 'preflight answered');

console.log('\nRegistration');
const alice = await creds('Alice_1', 'correct horse battery');
r = await api('/api/register', { method: 'POST', body: alice });
ok(r.status === 201 && r.json.token && r.json.user.username === 'Alice_1', 'register succeeds', JSON.stringify(r.json));
const aliceToken = r.json.token;
r = await api('/api/register', { method: 'POST', body: await creds('alice_1', 'other password') });
ok(r.status === 409 && r.json.error === 'username_taken', 'username is unique, case-insensitively');
r = await api('/api/register', { method: 'POST', body: { username: 'no spaces!', pw: alice.pw } });
ok(r.status === 400 && r.json.error === 'invalid_username', 'bad username rejected');
r = await api('/api/register', { method: 'POST', body: { username: 'bobby', pw: 'plain-text-password' } });
ok(r.status === 400 && r.json.error === 'invalid_password_hash', 'a non-hash "password" is rejected');
r = await fetch(BASE + '/api/register', { method: 'POST', body: 'x=1' });
ok(r.status === 415, 'wrong content type rejected');

console.log('\nStorage');
const row = JSON.parse(sql("SELECT username_lc, pw_salt, pw_hash, pw_algo FROM users WHERE username_lc='alice_1'").stdout)[0].results[0];
ok(row && row.pw_hash !== alice.pw && row.pw_hash.length === 64 && row.pw_salt.length === 32 && row.pw_algo === 'h1', 'stored value is salted + peppered, not the value the client sent');

console.log('\nLogin');
r = await api('/api/login', { method: 'POST', body: await creds('ALICE_1', 'correct horse battery') });
ok(r.status === 200 && r.json.token && r.json.user.username === 'Alice_1', 'login works (username is case-insensitive)');
r = await api('/api/login', { method: 'POST', body: await creds('Alice_1', 'wrong password') });
const wrongBody = JSON.stringify(r.json);
ok(r.status === 401 && r.json.error === 'invalid_credentials', 'wrong password -> 401');
r = await api('/api/login', { method: 'POST', body: await creds('nobody_here', 'whatever') });
ok(r.status === 401 && JSON.stringify(r.json) === wrongBody, 'unknown user gives the identical answer (no user enumeration)');

console.log('\nSessions');
r = await api('/api/me', { token: aliceToken });
ok(r.status === 200 && r.json.user.username === 'Alice_1', '/me with a valid token');
r = await api('/api/me');
ok(r.status === 401, '/me without a token -> 401');
const [pl, sig] = aliceToken.split('.');
const forged = Buffer.from(JSON.stringify({ sub: 'someone-else', tv: 0, exp: 9999999999 })).toString('base64url') + '.' + sig;
r = await api('/api/me', { token: forged });
ok(r.status === 401, 'forged token rejected');
r = await api('/api/me', { token: pl + '.' + sig.slice(0, -2) + 'AA' });
ok(r.status === 401, 'tampered signature rejected');
const carol = await creds('carol', 'carol pass');
let carolTok = (await api('/api/register', { method: 'POST', body: carol })).json.token;
r = await api('/api/logout-all', { method: 'POST', token: carolTok });
ok(r.status === 200, 'logout-all accepted');
r = await api('/api/me', { token: carolTok });
ok(r.status === 401, 'old token stops working after logout-all');
r = await api('/api/login', { method: 'POST', body: carol });
ok(r.status === 200, 'can log in again afterwards');
r = await api('/api/me', { token: r.json.token });
ok(r.status === 200, 'new token works');

console.log('\nBrute-force protection');
const bob = await creds('bobby', 'bobs real password');
await api('/api/register', { method: 'POST', body: bob });
let last;
for (let i = 0; i < 8; i++) last = await api('/api/login', { method: 'POST', body: await creds('bobby', 'guess' + i) });
ok(last.status === 401, '8 wrong guesses are answered normally');
r = await api('/api/login', { method: 'POST', body: bob });
ok(r.status === 429 && r.json.retry_after > 0, 'then the account is locked, even for the right password', JSON.stringify(r.json));
sql("DELETE FROM throttle WHERE key LIKE 'login:%'");

console.log('\nSign-up rate limit');
const results = [];
for (const n of ['dave', 'erin', 'frank']) results.push((await api('/api/register', { method: 'POST', body: await creds(n, 'pw ' + n) })).status);
ok(results.includes(429), 'a flood of sign-ups from one address gets 429', results.join(','));

console.log('\nMisc');
r = await api('/api/nope');
ok(r.status === 404, 'unknown route -> 404');
r = await api('/api/login');
ok(r.status === 405, 'wrong method -> 405');

console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
