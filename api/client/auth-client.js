/**
 * Bondam Run - browser helper for the account API.
 * Works as an ES module (<script type="module">) on GitHub Pages (HTTPS is required for crypto.subtle).
 *
 *   import { register, login, me, logout, getSession } from './auth-client.js';
 *   await register('alice', 'correct horse battery');
 *   const { user } = getSession();
 */
export const API_BASE = 'https://bondam-run-api.YOUR-SUBDOMAIN.workers.dev';   // <- printed by deploy.mjs
const STORE = 'bondam.session';
const ITERATIONS = 120000;               // runs on the player's device, not on Cloudflare's CPU budget

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

/** password -> 64 hex chars. The plain password never leaves the device. */
export async function hashPassword(username, password) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS, salt: enc.encode('bondam-run:v1:' + username.trim().toLowerCase()) },
    key, 256);
  return hex(bits);
}

async function call(path, { method = 'GET', body, token } = {}) {
  const res = await fetch(API_BASE + path, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(data.error || 'request_failed'); e.code = data.error; e.status = res.status; e.retryAfter = data.retry_after; throw e; }
  return data;
}

const save = (s) => { try { localStorage.setItem(STORE, JSON.stringify(s)); } catch { /* storage blocked */ } return s; };
export const getSession = () => { try { return JSON.parse(localStorage.getItem(STORE) || 'null'); } catch { return null; } };

export async function register(username, password) {
  const pw = await hashPassword(username, password);
  const r = await call('/api/register', { method: 'POST', body: { username: username.trim(), pw } });
  return save({ token: r.token, user: r.user });
}

export async function login(username, password) {
  const pw = await hashPassword(username, password);
  const r = await call('/api/login', { method: 'POST', body: { username: username.trim(), pw } });
  return save({ token: r.token, user: r.user });
}

/** Validates the saved session; swaps in a fresh token when the server offers one. */
export async function me() {
  const s = getSession();
  if (!s) return null;
  try {
    const r = await call('/api/me', { token: s.token });
    return save({ token: r.token || s.token, user: r.user });
  } catch (e) {
    if (e.status === 401) { logout(); return null; }
    throw e;                              // offline etc.: keep the session, caller decides
  }
}

export function logout() { try { localStorage.removeItem(STORE); } catch { /* ignore */ } }
export const logoutEverywhere = async () => { const s = getSession(); if (s) await call('/api/logout-all', { method: 'POST', token: s.token }); logout(); };

/** Friendly text for the error codes the API returns. */
export const explain = (e) => ({
  username_taken: 'That username is already taken.',
  invalid_username: 'Use 3-20 letters, numbers or underscores.',
  invalid_credentials: 'Wrong username or password.',
  too_many_attempts: 'Too many tries. Please wait ' + Math.ceil((e.retryAfter || 900) / 60) + ' minutes.',
}[e.code] || 'Something went wrong. Please try again.');
