// Shared cryptography for the private projects portal (browser, WebCrypto only).
//
// - Each project's files are encrypted with its own AES-256-GCM key (projects-portal/encrypt.mjs).
// - That project key is wrapped with the owner's RSA-OAEP public key; only the owner's private key,
//   kept in the owner's browser under a passphrase, can unwrap it (admin page).
// - A share link carries the project key, the recipient's name and an expiry date, encrypted with a
//   key derived from the share password. The link's token sits after the # and never reaches a server.

export const SHARE_ITERATIONS = 300_000;
export const OWNER_ITERATIONS = 600_000;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const text = { enc: (s) => enc.encode(s), dec: (b) => dec.decode(b) };

export function b64u(bytes) {
  let s = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i += 0x8000) s += String.fromCharCode(...view.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64u(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export const random = (n) => crypto.getRandomValues(new Uint8Array(n));

export async function passwordKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function seal(key, plain, aad) {
  const iv = random(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, plain);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return out;
}

export async function open(key, sealed, aad) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12), additionalData: enc.encode(aad) }, key, sealed.slice(12)));
}

export const projectKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);

// ---- share tokens -------------------------------------------------------------------------------

/** { pid, title, name, expires (ms), created (ms), key (raw 32 bytes) } + password → URL-safe token. */
export async function makeShareToken(share, password) {
  const salt = random(16);
  const key = await passwordKey(password, salt, SHARE_ITERATIONS);
  const body = enc.encode(JSON.stringify({ v: 1, p: share.pid, t: share.title, n: share.name, e: share.expires, c: share.created, k: b64u(share.key) }));
  const sealed = await seal(key, body, 'astra-share-v1');
  const out = new Uint8Array(1 + 16 + sealed.length);
  out[0] = 1;
  out.set(salt, 1);
  out.set(sealed, 17);
  return b64u(out);
}

/** Throws when the password is wrong or the token was altered. */
export async function readShareToken(token, password) {
  const bytes = unb64u(token);
  if (bytes[0] !== 1 || bytes.length < 60) throw new Error('bad-token');
  const key = await passwordKey(password, bytes.slice(1, 17), SHARE_ITERATIONS);
  const body = JSON.parse(dec.decode(await open(key, bytes.slice(17), 'astra-share-v1')));
  return { pid: body.p, title: body.t, name: body.n, expires: body.e, created: body.c, key: unb64u(body.k) };
}

/** The time on GitHub's servers (the Date header of a same-origin response); falls back to this device. */
export async function serverNow() {
  try {
    const res = await fetch(`/robots.txt?t=${Date.now()}`, { cache: 'no-store' });
    const date = Date.parse(res.headers.get('date') || '');
    if (Number.isFinite(date)) return date;
  } catch {
    // offline: use the device clock
  }
  return Date.now();
}

export function formatDate(ms) {
  return new Date(ms).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ---- session store shared with the service worker ------------------------------------------------

const DB = 'astra-projects';
function db() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('sessions', { keyPath: 'pid' });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveSession(session) {
  const d = await db();
  await new Promise((resolve, reject) => {
    const tx = d.transaction('sessions', 'readwrite');
    tx.objectStore('sessions').put(session);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

export async function deleteSession(pid) {
  const d = await db();
  await new Promise((resolve) => {
    const tx = d.transaction('sessions', 'readwrite');
    tx.objectStore('sessions').delete(pid);
    tx.oncomplete = resolve;
    tx.onerror = resolve;
  });
}

// ---- switched-off links ---------------------------------------------------------------------------

/** A link's id in the portal's list of switched-off links (revoked.json): a hash of project + creation time. */
export async function linkId(pid, created) {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(`${pid}:${created}`)));
  return Array.from(hash.slice(0, 12), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** The ids of the links the owner switched off. Throws when the list cannot be read. */
export async function revokedIds() {
  const res = await fetch(`/revoked.json?t=${Date.now()}`, { cache: 'no-store' });
  if (res.status === 404) return new Set();
  if (!res.ok) throw new Error(`revoked.json ${res.status}`);
  return new Set((await res.json()).revoked || []);
}
