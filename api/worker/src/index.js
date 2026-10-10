/**
 * Bondam Run - account API (Cloudflare Worker + D1).
 *
 * Endpoints (JSON in, JSON out):
 *   GET  /api/health
 *   POST /api/register    { username, pw }  -> 201 { token, user }
 *   POST /api/login       { username, pw }  -> 200 { token, user }
 *   GET  /api/me          (Bearer token)    -> 200 { user, token? }
 *   POST /api/logout-all  (Bearer token)    -> 200 { ok }
 *
 * `pw` is NOT the plain password. The browser derives it (PBKDF2, 120k iterations, see
 * client/auth-client.js) and sends 64 hex chars. Because that value is effectively the
 * password, the server never stores it as-is: it stores HMAC-SHA256(PEPPER, salt:pw) with a
 * random per-user salt. PEPPER is a Worker secret, so a leaked database alone cannot be
 * used to test password guesses.
 *
 * Free-plan note: Workers get ~10 ms CPU per request, so the expensive stretching is done on
 * the player's device and the server does only cheap, constant-time work.
 *
 * Secrets (wrangler secret): PEPPER, SESSION_SECRET.   Vars: ALLOWED_ORIGINS (comma list).
 * Binding: DB (D1).
 */

const enc = new TextEncoder();
const USER_RE = /^[A-Za-z0-9_]{3,20}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const TOKEN_TTL = 30 * 24 * 3600;       // sessions last 30 days
const MAX_BODY = 2048;                  // bytes; auth bodies are tiny
const DUMMY_SALT = '00000000000000000000000000000000';

const LIMITS = {
  loginUser: { max: 8,  window: 900 },  // 8 failed logins / 15 min per username
  loginIp:   { max: 30, window: 900 },  // 30 failed logins / 15 min per IP
  register:  { max: 5,  window: 3600 }, // 5 sign-ups / hour per IP
};

class HttpError extends Error {
  constructor(status, code, extra) { super(code); this.status = status; this.code = code; this.extra = extra || {}; }
}

/* ---------------------------------------------------------------- helpers */

const now = () => Math.floor(Date.now() / 1000);
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

function safeEqual(a, b) {               // constant-time string compare
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

const keyCache = new Map();
async function hmacKey(secret) {
  if (!secret) throw new HttpError(500, 'not_configured');
  if (!keyCache.has(secret)) {
    keyCache.set(secret, await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']));
  }
  return keyCache.get(secret);
}
const hmac = async (secret, data) => crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(data));

/** Stored form of a password: HMAC(pepper, "salt:clientHash"). */
const serverHash = async (env, salt, clientHash) => toHex(await hmac(env.PEPPER, `${salt}:${clientHash}`));

/* ---------------------------------------------------------------- sessions */

async function signToken(env, { sub, tv }) {
  const payload = b64url(enc.encode(JSON.stringify({ sub, tv, exp: now() + TOKEN_TTL })));
  return `${payload}.${b64url(await hmac(env.SESSION_SECRET, payload))}`;
}

async function verifyToken(env, token) {
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = b64url(await hmac(env.SESSION_SECRET, payload));
  if (!safeEqual(expected, sig)) return null;
  let p;
  try { p = JSON.parse(new TextDecoder().decode(unb64url(payload))); } catch { return null; }
  return p && p.exp > now() ? p : null;
}

async function requireUser(request, env) {
  const m = /^Bearer ([A-Za-z0-9_.-]+)$/.exec(request.headers.get('Authorization') || '');
  const p = m && (await verifyToken(env, m[1]));
  if (!p) throw new HttpError(401, 'unauthorized');
  const u = await env.DB.prepare('SELECT id, username, token_version FROM users WHERE id = ?').bind(p.sub).first();
  if (!u || u.token_version !== p.tv) throw new HttpError(401, 'unauthorized');
  return { user: u, payload: p };
}

/* ---------------------------------------------------------------- throttling (D1) */

async function throttlePeek(env, keys, limit) {
  const marks = keys.map(() => '?').join(',');
  const { results } = await env.DB.prepare(`SELECT key, n, win_start FROM throttle WHERE key IN (${marks})`).bind(...keys).all();
  const t = now();
  for (const r of results || []) {
    if (t - r.win_start < limit.window && r.n >= limit.max) {
      throw new HttpError(429, 'too_many_attempts', { retry_after: r.win_start + limit.window - t });
    }
  }
}

/** Prepared statement that counts one event in the current window (starts a new window when the old one expired). */
function failStmt(env, key, limit) {
  const t = now();
  return env.DB.prepare(
    `INSERT INTO throttle (key, n, win_start) VALUES (?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET
       n = CASE WHEN ? - win_start >= ? THEN 1 ELSE n + 1 END,
       win_start = CASE WHEN ? - win_start >= ? THEN ? ELSE win_start END
     RETURNING n, win_start`
  ).bind(key, t, t, limit.window, t, limit.window, t);
}

/** Count one event; returns the new count inside the current window. */
async function throttleHit(env, key, limit) {
  return failStmt(env, key, limit).first();
}

/* ---------------------------------------------------------------- http plumbing */

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const local = env.ALLOW_LOCALHOST === '1' && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin || '');
  const h = { Vary: 'Origin' };
  if (origin && (allowed.includes(origin) || local)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    h['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}

function reply(request, env, status, body, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...corsHeaders(request, env),
      ...(extraHeaders || {}),
    },
  });
}

async function readJson(request) {
  if (!(request.headers.get('Content-Type') || '').includes('application/json')) throw new HttpError(415, 'unsupported_media_type');
  const text = await request.text();
  if (text.length > MAX_BODY) throw new HttpError(413, 'body_too_large');
  try { return JSON.parse(text); } catch { throw new HttpError(400, 'bad_json'); }
}

function credentials(body) {
  const username = body && typeof body.username === 'string' ? body.username.trim() : '';
  const pw = body && typeof body.pw === 'string' ? body.pw : '';
  if (!USER_RE.test(username)) throw new HttpError(400, 'invalid_username', { hint: '3-20 letters, numbers or underscore' });
  if (!HEX64_RE.test(pw)) throw new HttpError(400, 'invalid_password_hash');
  return { username, pw };
}

const clientIp = (request) => request.headers.get('CF-Connecting-IP') || 'unknown';

/* ---------------------------------------------------------------- handlers */

async function register(request, env) {
  const body = await readJson(request);
  const { username, pw } = credentials(body);

  const hit = await throttleHit(env, `reg:${clientIp(request)}`, LIMITS.register);
  if (hit.n > LIMITS.register.max) {
    throw new HttpError(429, 'too_many_attempts', { retry_after: hit.win_start + LIMITS.register.window - now() });
  }

  const id = randHex(16), salt = randHex(16), t = now();
  const hash = await serverHash(env, salt, pw);
  try {
    await env.DB.prepare(
      `INSERT INTO users (id, username, username_lc, pw_salt, pw_hash, pw_algo, token_version, created_at, last_login_at)
       VALUES (?, ?, ?, ?, ?, 'h1', 0, ?, ?)`
    ).bind(id, username, username.toLowerCase(), salt, hash, t, t).run();
  } catch (e) {
    if (String((e && e.message) || e).includes('UNIQUE')) throw new HttpError(409, 'username_taken');
    throw e;
  }
  return [201, { token: await signToken(env, { sub: id, tv: 0 }), user: { id, username } }];
}

async function login(request, env, ctx) {
  const body = await readJson(request);
  const { username, pw } = credentials(body);
  const lc = username.toLowerCase(), ip = clientIp(request);
  const userKey = `login:u:${lc}`, ipKey = `login:ip:${ip}`;

  await throttlePeek(env, [userKey], LIMITS.loginUser);
  await throttlePeek(env, [ipKey], LIMITS.loginIp);

  const u = await env.DB.prepare('SELECT id, username, pw_salt, pw_hash, token_version FROM users WHERE username_lc = ?').bind(lc).first();
  // Always do the same amount of work, whether or not the user exists.
  const candidate = await serverHash(env, u ? u.pw_salt : DUMMY_SALT, pw);
  if (!u || !safeEqual(candidate, u.pw_hash)) {
    await env.DB.batch([failStmt(env, userKey, LIMITS.loginUser), failStmt(env, ipKey, LIMITS.loginIp)]);
    throw new HttpError(401, 'invalid_credentials');
  }

  await env.DB.batch([
    env.DB.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').bind(now(), u.id),
    env.DB.prepare('DELETE FROM throttle WHERE key = ?').bind(userKey),
  ]);
  if (Math.random() < 0.02) {           // opportunistic clean-up, no cron needed
    ctx.waitUntil(env.DB.prepare('DELETE FROM throttle WHERE win_start < ?').bind(now() - 86400).run());
  }
  return [200, { token: await signToken(env, { sub: u.id, tv: u.token_version }), user: { id: u.id, username: u.username } }];
}

async function me(request, env) {
  const { user, payload } = await requireUser(request, env);
  const out = { user: { id: user.id, username: user.username } };
  if (payload.exp - now() < TOKEN_TTL / 2) out.token = await signToken(env, { sub: user.id, tv: user.token_version });
  return [200, out];
}

async function logoutAll(request, env) {
  const { user } = await requireUser(request, env);
  await env.DB.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').bind(user.id).run();
  return [200, { ok: true }];
}

const ROUTES = {
  'GET /api/health': async () => [200, { ok: true, service: 'bondam-run-api' }],
  'POST /api/register': register,
  'POST /api/login': login,
  'GET /api/me': me,
  'POST /api/logout-all': logoutAll,
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request, env) });
      if (url.pathname === '/') return reply(request, env, 200, { name: 'bondam-run-api' });
      const handler = ROUTES[`${request.method} ${url.pathname}`];
      if (!handler) {
        const known = Object.keys(ROUTES).some((r) => r.endsWith(` ${url.pathname}`));
        throw new HttpError(known ? 405 : 404, known ? 'method_not_allowed' : 'not_found');
      }
      const [status, body] = await handler(request, env, ctx);
      return reply(request, env, status, body);
    } catch (e) {
      if (e instanceof HttpError) {
        const headers = e.extra.retry_after ? { 'Retry-After': String(e.extra.retry_after) } : undefined;
        return reply(request, env, e.status, { error: e.code, ...e.extra }, headers);
      }
      console.error('unhandled', e && e.stack || e);
      return reply(request, env, 500, { error: 'server_error' });
    }
  },
};
