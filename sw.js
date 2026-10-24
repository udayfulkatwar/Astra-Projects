/*
 * ASTRA DWELL private projects: serves a project's files, decrypted, under /x/<project id>/ while a
 * share is open in this browser. The share (project key, recipient, expiry) is saved by the viewer
 * page in IndexedDB once the password is right. Every HTML page gets the recipient's name as a
 * watermark. After the expiry date, or once the owner has switched the link off (revoked.json),
 * nothing is served.
 */
const enc = new TextEncoder();
const dec = new TextDecoder();
const projects = new Map(); // pid -> { created, key, manifest, session }

self.addEventListener('install', (event) => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'forget') projects.delete(event.data.pid);
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith('/x/') || event.request.method !== 'GET') return;
  event.respondWith(serve(url));
});

function readSession(pid) {
  return new Promise((resolve) => {
    const req = indexedDB.open('astra-projects', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('sessions', { keyPath: 'pid' });
    req.onerror = () => resolve(null);
    req.onsuccess = () => {
      const tx = req.result.transaction('sessions', 'readonly');
      const get = tx.objectStore('sessions').get(pid);
      get.onsuccess = () => resolve(get.result || null);
      get.onerror = () => resolve(null);
    };
  });
}

// The owner's list of switched-off links, read at most once a minute.
let revoked = { at: 0, ids: null, loading: null };
function revokedIds() {
  if (revoked.ids && Date.now() - revoked.at < 60_000) return revoked.ids;
  revoked.loading ||= fetch(`/revoked.json?t=${Date.now()}`, { cache: 'no-store' })
    .then(async (res) => {
      if (!res.ok && res.status !== 404) throw new Error(`revoked.json ${res.status}`);
      revoked = { at: Date.now(), ids: new Set(res.ok ? (await res.json()).revoked || [] : []), loading: null };
      return revoked.ids;
    })
    .catch((error) => {
      revoked.loading = null;
      // A short network hiccup keeps the last list for a few minutes; after that nothing is served.
      if (revoked.ids && Date.now() - revoked.at < 300_000) return revoked.ids;
      throw error;
    });
  return revoked.loading;
}

// Same id as linkId() in assets/crypto.js.
async function linkId(pid, created) {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(`${pid}:${created}`)));
  return Array.from(hash.slice(0, 12), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function decryptFile(pid, label, key, url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`missing ${url}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: enc.encode(`${pid}/${label}`) }, key, bytes.slice(12)));
}

async function project(pid) {
  const session = await readSession(pid);
  if (!session) return { locked: true };
  if (Date.now() + (session.offset || 0) > session.expires) return { expired: session };
  if ((await revokedIds()).has(await linkId(pid, session.created))) return { revoked: true };
  let p = projects.get(pid);
  if (!p || p.created !== session.created) {
    const key = await crypto.subtle.importKey('raw', session.key, 'AES-GCM', false, ['decrypt']);
    const manifest = JSON.parse(dec.decode(await decryptFile(pid, 'manifest', key, `/p/${pid}/manifest.bin`)));
    p = { created: session.created, key, manifest, session };
    projects.set(pid, p);
  }
  return p;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function day(ms) {
  return new Date(ms).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

function dayTime(ms) {
  return new Date(ms).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// A tiled watermark over the whole app, plus a small label; neither takes clicks.
function watermark(session) {
  const line = `${session.name} · ${day(Date.now())} · ASTRA DWELL`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="460" height="240"><g transform="rotate(-24 230 120)"><text x="230" y="128" text-anchor="middle" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="20" font-weight="600" fill="rgba(255,255,255,0.17)" stroke="rgba(0,0,0,0.14)" stroke-width="0.6">${esc(line)}</text></g></svg>`;
  const tile = `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
  return `<div aria-hidden="true" style="position:fixed;inset:0;z-index:2147483647;pointer-events:none;background-image:${esc(tile)};background-repeat:repeat"></div><div aria-hidden="true" style="position:fixed;left:max(10px,env(safe-area-inset-left));bottom:max(10px,env(safe-area-inset-bottom));z-index:2147483647;pointer-events:none;padding:5px 9px;border-radius:6px;background:rgba(0,0,0,.6);color:#fff;font:600 11px/1.3 system-ui,-apple-system,Segoe UI,sans-serif;letter-spacing:.02em">Private preview for ${esc(session.name)} · until ${esc(dayTime(session.expires))}</div>`;
}

function page(status, message) {
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>ASTRA DWELL · Private preview</title><body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#050505;color:#f2f2ef;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:24px;text-align:center"><div><p style="font:12px ui-monospace,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;color:#85857f">ASTRA DWELL · Private preview</p><p>${esc(message)}</p></div></body>`;
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

async function serve(url) {
  const m = url.pathname.match(/^\/x\/([a-z0-9]+)\/(.*)$/);
  if (!m) return page(404, 'Not found.');
  const pid = m[1];
  let path = decodeURIComponent(m[2]) || 'index.html';
  if (path.endsWith('/')) path += 'index.html';
  let p;
  try {
    p = await project(pid);
  } catch {
    return page(500, 'This preview could not be opened. Please try your link again.');
  }
  if (p.locked) return page(403, 'This preview is locked. Open the link you were sent and enter its password.');
  if (p.expired) return page(403, `This preview link expired on ${dayTime(p.expired.expires)}.`);
  if (p.revoked) return page(403, 'This preview link was switched off. Ask ASTRA DWELL for a new one.');
  const file = p.manifest.files[path];
  if (!file) return new Response('Not found', { status: 404 });
  const bytes = await decryptFile(pid, file.id, p.key, `/p/${pid}/${file.id}.bin`);
  const headers = { 'Content-Type': file.type, 'Cache-Control': 'no-store' };
  if (file.type.startsWith('text/html')) {
    const html = dec.decode(bytes);
    const marked = html.includes('</body>') ? html.replace('</body>', `${watermark(p.session)}</body>`) : html + watermark(p.session);
    return new Response(marked, { headers });
  }
  return new Response(bytes, { headers });
}
