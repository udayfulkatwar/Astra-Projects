/*
 * ASTRA DWELL private projects: serves a project's files, decrypted, under /x/<project id>/ while a
 * share is open in this browser. The share (project key, recipient, expiry) is saved by the viewer
 * page in IndexedDB once the password is right. Every HTML page gets the recipient's name and the
 * link's reference code as a watermark, a near-invisible pattern that encodes the reference (it
 * survives screenshots and recordings; projects-portal/trace.mjs reads it back), a script that stamps
 * the same marks into any image the app exports, and a Content Security Policy that keeps the app on
 * this site. After the expiry date, or once the owner has switched the link off (revoked.json),
 * nothing is served and the saved key is deleted from this browser.
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

function deleteSession(pid) {
  return new Promise((resolve) => {
    const req = indexedDB.open('astra-projects', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('sessions', { keyPath: 'pid' });
    req.onerror = () => resolve();
    req.onsuccess = () => {
      const tx = req.result.transaction('sessions', 'readwrite');
      tx.objectStore('sessions').delete(pid);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
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
  if (Date.now() + (session.offset || 0) > session.expires) {
    projects.delete(pid);
    await deleteSession(pid);
    return { expired: session };
  }
  const id = await linkId(pid, session.created);
  if ((await revokedIds()).has(id)) {
    projects.delete(pid);
    await deleteSession(pid);
    return { revoked: true };
  }
  let p = projects.get(pid);
  if (!p || p.created !== session.created) {
    const key = await crypto.subtle.importKey('raw', session.key, 'AES-GCM', false, ['decrypt']);
    const manifest = JSON.parse(dec.decode(await decryptFile(pid, 'manifest', key, `/p/${pid}/manifest.bin`)));
    p = { created: session.created, key, manifest, session, ref: id.slice(0, 6).toUpperCase() };
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

// ---- marks ------------------------------------------------------------------------------------------
// The forensic pattern (keep in step with the stamp script below and projects-portal/trace.mjs):
// a 160 x 260 px tile of 8 x 13 cells of 20 px. Each cell is a fine 4 px grain: a fixed 5 x 5 key
// (KEY) of lighter / darker blocks, flipped when the cell's bit is 1. Row 0 is a fixed sync row; the
// 32 bits (the 6-character reference = 24 bits, then a CRC-8 of it) fill rows 1–4, again inverted in
// rows 5–8 and again in rows 9–12. Since 1 Nov 2026 it is stamped only into images the app exports (its
// Screenshot button), blended with "overlay" from a near-neutral grey tile (129 / 126 of 255); it is no
// longer drawn on screen, where viewers could still see a faint dotted pattern on dark panels. Screen
// captures are traced by the visible name / Ref watermark. The decoder correlates with the key, which
// cancels the picture behind it, and the checksum guards the result.
const GRAIN_LIGHT = '#818181', GRAIN_DARK = '#7e7e7e';
const SYNC = [1, 0, 1, 1, 0, 0, 1, 0];
const KEY = '1001110100011011011110000';
function crc8(bytes) {
  let c = 0xff; // non-zero start: an all-zero (blank) reading is never valid
  for (const x of bytes) {
    c ^= x;
    for (let i = 0; i < 8; i++) c = c & 0x80 ? ((c << 1) ^ 0x07) & 0xff : (c << 1) & 0xff;
  }
  return c;
}
function markBits(ref) {
  const v = parseInt(ref, 16) & 0xffffff;
  const word = ((v << 8) | crc8([v >>> 16, (v >>> 8) & 0xff, v & 0xff])) >>> 0;
  const data = Array.from({ length: 32 }, (_, i) => (word >>> (31 - i)) & 1);
  return [...SYNC, ...data, ...data.map((b) => 1 - b), ...data];
}
/** Dark 4 px blocks of the tile, as [x, y] pairs. */
function darkBlocks(ref) {
  const out = [];
  markBits(ref).forEach((b, i) => {
    const cx = (i % 8) * 20, cy = Math.floor(i / 8) * 20;
    for (let k = 0; k < 25; k++) if ((b ^ Number(KEY[k])) === 1) out.push([cx + (k % 5) * 4, cy + Math.floor(k / 5) * 4]);
  });
  return out;
}
// A tiled watermark over the whole app (name, reference, date; its placement also varies with the
// reference) and a small label; neither takes clicks.
function watermark(session, ref) {
  const line = `${session.name} · Ref ${ref} · ${day(Date.now())} · ASTRA DWELL`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="520" height="260"><g transform="rotate(-24 260 130)"><text x="260" y="138" text-anchor="middle" font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="19" font-weight="600" fill="rgba(255,255,255,0.17)" stroke="rgba(0,0,0,0.14)" stroke-width="0.6">${esc(line)}</text></g></svg>`;
  const tile = `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
  const ox = parseInt(ref.slice(0, 2), 16) % 260, oy = parseInt(ref.slice(2, 4), 16) % 130;
  return `<div aria-hidden="true" data-astra-mark style="position:fixed;inset:0;z-index:2147483647;pointer-events:none;background-image:${esc(tile)};background-repeat:repeat;background-position:${ox}px ${oy}px"></div><div aria-hidden="true" data-astra-mark style="position:fixed;left:max(10px,env(safe-area-inset-left));bottom:max(10px,env(safe-area-inset-bottom));z-index:2147483647;pointer-events:none;padding:5px 9px;border-radius:6px;background:rgba(0,0,0,.6);color:#fff;font:600 11px/1.3 system-ui,-apple-system,Segoe UI,sans-serif;letter-spacing:.02em">Private preview for ${esc(session.name)} · Ref ${esc(ref)} · until ${esc(dayTime(session.expires))}</div>`;
}

// Served as /x/<pid>/__astra-mark.js: stamps the same marks into every image the app exports
// (toDataURL / toBlob of an on-page canvas, e.g. the app's Screenshot button), and puts the marks
// back if a script removes them.
function stampScript(session, ref) {
  const cfg = JSON.stringify({ line: `${session.name} · Ref ${ref} · ${day(Date.now())} · ASTRA DWELL`, label: `Private preview for ${session.name} · Ref ${ref}`, dark: darkBlocks(ref), light: GRAIN_LIGHT, shade: GRAIN_DARK });
  return `(() => {
  const M = ${cfg};
  const P = HTMLCanvasElement.prototype, toURL = P.toDataURL, toBlob = P.toBlob;
  let busy = false;
  function stamp(src) {
    const c = document.createElement('canvas'); c.width = src.width; c.height = src.height;
    const g = c.getContext('2d'); g.drawImage(src, 0, 0);
    const k = 1;
    // forensic pattern, same tile as the live overlay (160 x 260 px at the canvas scale)
    const t = document.createElement('canvas'); t.width = Math.round(160 * k); t.height = Math.round(260 * k);
    const tg = t.getContext('2d'); tg.fillStyle = M.light; tg.fillRect(0, 0, t.width, t.height); tg.fillStyle = M.shade;
    for (const [x, y] of M.dark) tg.fillRect(Math.round(x * k), Math.round(y * k), Math.round(4 * k), Math.round(4 * k));
    g.save(); g.globalCompositeOperation = 'overlay'; g.fillStyle = g.createPattern(t, 'repeat'); g.fillRect(0, 0, c.width, c.height); g.restore();
    g.save(); g.font = '600 ' + Math.round(19 * k) + 'px system-ui,sans-serif'; g.textAlign = 'center';
    g.fillStyle = 'rgba(255,255,255,0.22)'; g.strokeStyle = 'rgba(0,0,0,0.16)'; g.lineWidth = 0.8 * k;
    for (let y = -c.height; y < c.height * 2; y += 260 * k) for (let x = -c.width; x < c.width * 2; x += 520 * k) {
      g.save(); g.translate(x, y); g.rotate(-0.42); g.strokeText(M.line, 0, 0); g.fillText(M.line, 0, 0); g.restore();
    }
    g.restore();
    g.font = '600 ' + Math.round(13 * k) + 'px system-ui,sans-serif'; const w = g.measureText(M.label).width;
    g.fillStyle = 'rgba(0,0,0,0.6)'; g.fillRect(10 * k, c.height - 34 * k, w + 18 * k, 24 * k);
    g.fillStyle = '#fff'; g.fillText(M.label, 19 * k, c.height - 17 * k);
    return c;
  }
  const exported = (cv) => cv.isConnected && cv.width >= 320 && cv.height >= 200;
  P.toDataURL = function (...a) { if (busy || !exported(this)) return toURL.apply(this, a); busy = true; try { return toURL.apply(stamp(this), a); } finally { busy = false; } };
  P.toBlob = function (cb, ...a) { if (busy || !exported(this)) return toBlob.call(this, cb, ...a); busy = true; try { return toBlob.call(stamp(this), cb, ...a); } finally { busy = false; } };
  // put the overlay back if it is removed or hidden
  const keep = document.querySelectorAll('[data-astra-mark]');
  const saved = Array.from(keep, (n) => [n, n.getAttribute('style')]);
  const fix = () => {
    for (const [n, st] of saved) {
      if (!n.isConnected) document.body.appendChild(n);
      if (n.getAttribute('style') !== st) n.setAttribute('style', st);
      if (n.hidden) n.hidden = false;
    }
  };
  const mo = new MutationObserver(fix);
  mo.observe(document.body, { childList: true });
  for (const [n] of saved) mo.observe(n, { attributes: true });
})();`;
}

// The apps only ever talk to this site: no outside scripts, connections or frames.
const APP_CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' blob:; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' data: blob:; frame-ancestors 'self'; base-uri 'none'; form-action 'none'; object-src 'none'";

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
  if (path === '__astra-mark.js') return new Response(stampScript(p.session, p.ref), { headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' } });
  const file = p.manifest.files[path];
  if (!file) return new Response('Not found', { status: 404 });
  const bytes = await decryptFile(pid, file.id, p.key, `/p/${pid}/${file.id}.bin`);
  const headers = { 'Content-Type': file.type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
  if (file.type.startsWith('text/html')) {
    const html = dec.decode(bytes);
    const marks = `${watermark(p.session, p.ref)}<script src="/x/${pid}/__astra-mark.js"></script>`;
    const meta = `<meta name="astra-mark" content="${esc(`${p.session.name}|${p.ref}`)}">`;
    let marked = html.includes('</head>') ? html.replace('</head>', `${meta}</head>`) : meta + html;
    marked = marked.includes('</body>') ? marked.replace('</body>', `${marks}</body>`) : marked + marks;
    return new Response(marked, { headers: { ...headers, 'Content-Security-Policy': APP_CSP, 'X-Frame-Options': 'SAMEORIGIN' } });
  }
  return new Response(bytes, { headers });
}
