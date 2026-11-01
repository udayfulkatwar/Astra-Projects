// "Views" on the admin page: how often each preview was opened and for how long it was on screen.
//
// The numbers come from the owner's open log (Google Apps Script, projects-portal/apps-script/open-log.gs):
// the viewer reports each viewing (open, a heartbeat every minute with the seconds on screen, close);
// the script's read address, protected by a read key, returns one summary per viewing. The read key is
// stored on this device locked with the owner key. Everything from the log is shown as text only (anyone
// can post to a web app address, so rows are treated as untrusted).
import { LOG_URL } from './config.js?v=166e6947fa';
import { b64u, unb64u, text } from './crypto.js?v=166e6947fa';

const $ = (id) => document.getElementById(id);
const KEY_STORE = 'astra-views-key';
const SVG = 'http://www.w3.org/2000/svg';
let ctx = null; // { privateKey, publicKey (CryptoKey), titles: Map pid -> title }
let loading = false;

const store = {
  get: () => { try { return localStorage.getItem(KEY_STORE); } catch { return null; } },
  set: (v) => { try { localStorage.setItem(KEY_STORE, v); return true; } catch { return false; } },
  del: () => { try { localStorage.removeItem(KEY_STORE); } catch { /* ignore */ } },
};

function say(msg, kind = '') {
  $('views-state').textContent = msg;
  $('views-state').className = `small ${kind}`;
}

const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  n.append(...kids);
  return n;
};
const svg = (tag, attrs = {}) => {
  const n = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  return n;
};

/** 0 → "0 min", 45 → "<1 min", 3900 → "1 h 05 min" */
export function duration(secs) {
  if (!secs) return '0 min';
  if (secs < 60) return '<1 min';
  const m = Math.round(secs / 60);
  if (m < 60) return `${m} min`;
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')} min`;
}
const when = (ms) => new Date(ms).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const dayKey = (ms) => {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};

async function readKey() {
  const sealed = store.get();
  if (!sealed || !ctx?.privateKey) return null;
  try {
    return text.dec(new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, ctx.privateKey, unb64u(sealed))));
  } catch {
    return null;
  }
}

/** Called by the admin page once the owner key is unlocked. */
export function initViews(context) {
  ctx = context;
  if (!LOG_URL) {
    $('views-body').hidden = true;
    $('views-key-form').hidden = true;
    say('The open log is not set up yet, so there is nothing to show. Setting it up takes about 5 minutes (free): see "Optional open log" in projects-portal/README.md, or ask Claude.');
    return;
  }
  refresh();
}

async function refresh() {
  if (!ctx || !LOG_URL || loading) return;
  const key = await readKey();
  if (!key) {
    $('views-body').hidden = true;
    $('views-key-form').hidden = false;
    say('');
    return;
  }
  loading = true;
  say('Loading…');
  const days = Number($('views-days').value) || 30;
  let data;
  try {
    const res = await fetch(`${LOG_URL}?key=${encodeURIComponent(key)}&days=${days}`, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    data = await res.json();
  } catch {
    loading = false;
    return say('The open log could not be reached just now. Try Refresh in a moment.', 'error');
  }
  loading = false;
  if (!data.ok) {
    if (data.error === 'bad-key') {
      store.del();
      $('views-key-form').hidden = false;
      $('views-body').hidden = true;
      return say('The open log did not accept the saved read key. Paste it again.', 'error');
    }
    return say(data.error === 'no-read-key' ? 'The open log has no read key yet: run setupReadKey once in the Apps Script editor.' : 'The open log answered with an error.', 'error');
  }
  $('views-key-form').hidden = true;
  $('views-body').hidden = false;
  render(data, days);
  say(`Updated ${when(data.generated || Date.now())}.`);
}

function render(data, days) {
  const views = (Array.isArray(data.views) ? data.views : []).map((v) => ({
    pid: String(v.pid || ''),
    title: ctx.titles.get(String(v.pid)) || String(v.title || v.pid || 'Unknown project'),
    ref: String(v.ref || ''),
    name: String(v.name || ''),
    device: String(v.device || ''),
    start: Number(v.start) || 0,
    last: Number(v.last) || 0,
    secs: Math.max(0, Number(v.secs) || 0),
  })).filter((v) => v.start);
  const wrong = Object.values(data.wrong || {}).reduce((a, n) => a + (Number(n) || 0), 0);
  const total = views.reduce((a, v) => a + v.secs, 0);
  const people = new Set(views.map((v) => `${v.pid}:${v.ref}`)).size;

  // tiles
  const tile = (value, what, sub = '') => el('div', { className: 'tile' }, el('div', { className: 'what', textContent: what }), el('div', { className: 'value', textContent: value }), el('div', { className: 'sub', textContent: sub }));
  $('views-tiles').replaceChildren(
    tile(String(views.length), 'Opens', `in the last ${days} days`),
    tile(String(people), 'People', 'different links opened'),
    tile(duration(total), 'Time on screen', 'all opens together'),
    tile(views.length ? duration(total / views.length) : '—', 'Average', 'per open'),
    tile(String(wrong), 'Wrong passwords', wrong ? 'tries with a wrong password' : 'none'),
  );

  // opens per day (per week beyond 90 days)
  const weekly = days > 90;
  const buckets = [];
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const step = weekly ? 7 : 1;
  const count = Math.ceil(days / step);
  for (let i = count - 1; i >= 0; i--) {
    const start = new Date(now);
    start.setDate(start.getDate() - i * step - (step - 1));
    buckets.push({ start: start.getTime(), end: start.getTime() + step * 86400000, opens: 0, secs: 0 });
  }
  for (const v of views) {
    const b = buckets.find((x) => v.start >= x.start && v.start < x.end);
    if (b) {
      b.opens++;
      b.secs += v.secs;
    }
  }
  chart(buckets, weekly);

  // by project
  const byProject = new Map();
  for (const v of views) {
    const p = byProject.get(v.pid) || { title: v.title, opens: 0, links: new Set(), secs: 0, last: 0 };
    p.opens++;
    p.links.add(v.ref);
    p.secs += v.secs;
    p.last = Math.max(p.last, v.last);
    byProject.set(v.pid, p);
  }
  const cell = (t, num = false) => el('td', { textContent: t, className: num ? 'num' : '' });
  const empty = (cols) => el('tr', {}, el('td', { colSpan: cols, className: 'small', textContent: 'No opens in this period.' }));
  const projRows = [...byProject.values()].sort((a, b) => b.opens - a.opens || b.last - a.last);
  $('views-projects').replaceChildren(...(projRows.length ? projRows.map((p) => el('tr', {}, cell(p.title), cell(String(p.opens), true), cell(String(p.links.size), true), cell(duration(p.secs), true), cell(duration(p.secs / p.opens), true), cell(when(p.last)))) : [empty(6)]));

  // by link
  const byLink = new Map();
  for (const v of views) {
    const k = `${v.pid}:${v.ref}`;
    const l = byLink.get(k) || { name: v.name, title: v.title, ref: v.ref, opens: 0, secs: 0, last: 0, device: '' };
    l.opens++;
    l.secs += v.secs;
    if (v.last >= l.last) {
      l.last = v.last;
      l.device = v.device;
    }
    byLink.set(k, l);
  }
  const linkRows = [...byLink.values()].sort((a, b) => b.last - a.last);
  $('views-links').replaceChildren(...(linkRows.length ? linkRows.map((l) => el('tr', {}, cell(l.name || '—'), cell(l.title), el('td', { className: 'mono', textContent: l.ref }), cell(String(l.opens), true), cell(duration(l.secs), true), cell(duration(l.secs / l.opens), true), cell(when(l.last)), cell(l.device))) : [empty(8)]));
}

/** Single-series bar chart (one hue, no legend), recessive grid, hover tooltip per bar. */
function chart(buckets, weekly) {
  const box = $('views-chart');
  // drawn at the box's real width so the 11 px labels stay 11 px on a phone
  const W = Math.max(300, Math.round(box.clientWidth || 720)), H = W < 500 ? 170 : 200, padL = 30, padB = 22, padT = 8;
  lastChart = [buckets, weekly];
  const max = Math.max(1, ...buckets.map((b) => b.opens));
  const nice = max <= 4 ? max : Math.ceil(max / 4) * 4;
  const plotW = W - padL, plotH = H - padB - padT;
  const slot = plotW / buckets.length;
  const bw = Math.max(2, Math.min(28, slot - 2)); // 2 px surface gap between bars
  const s = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Opens per ${weekly ? 'week' : 'day'}; the tables below hold the same numbers` });
  const ticks = nice <= 4 ? Array.from({ length: nice + 1 }, (_, i) => i) : [0, nice / 4, nice / 2, (3 * nice) / 4, nice];
  for (const t of ticks) {
    const y = padT + plotH - (t / nice) * plotH;
    s.append(svg('line', { x1: padL, x2: W, y1: y, y2: y, class: 'grid' }));
    const lab = svg('text', { x: padL - 6, y: y + 4, 'text-anchor': 'end', class: 'axis' });
    lab.textContent = String(t);
    s.append(lab);
  }
  const tip = el('div', { className: 'chart-tip', hidden: true });
  const fmt = (ms) => new Date(ms).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  buckets.forEach((b, i) => {
    const x = padL + i * slot + (slot - bw) / 2;
    const h = (b.opens / nice) * plotH;
    const y = padT + plotH - h;
    // hit target: the whole slot, taller than the bar
    const hit = svg('rect', { x: padL + i * slot, y: padT, width: slot, height: plotH, fill: 'transparent', class: 'hit' });
    const r = Math.min(4, bw / 2, h);
    const bar = h > 0 ? svg('path', { class: 'bar', d: `M${x},${padT + plotH} V${y + r} Q${x},${y} ${x + r},${y} H${x + bw - r} Q${x + bw},${y} ${x + bw},${y + r} V${padT + plotH} Z` }) : svg('rect', { x, y: padT + plotH - 1, width: bw, height: 1, class: 'bar', opacity: 0.35 });
    const show = () => {
      tip.textContent = `${weekly ? `Week of ${fmt(b.start)}` : fmt(b.start)}: ${b.opens} open${b.opens === 1 ? '' : 's'} · ${duration(b.secs)} on screen`;
      tip.hidden = false;
      const rect = box.getBoundingClientRect();
      // centred over the bar, but kept inside the chart at both ends
      const half = tip.offsetWidth / 2;
      const cx = ((x + bw / 2) / W) * rect.width;
      tip.style.left = `${Math.min(rect.width - half, Math.max(half, cx))}px`;
      tip.style.top = `${(Math.max(padT, y) / H) * rect.height - 6}px`;
      bar.classList.add('on');
    };
    const hide = () => {
      tip.hidden = true;
      bar.classList.remove('on');
    };
    hit.addEventListener('pointerenter', show);
    hit.addEventListener('pointerleave', hide);
    s.append(hit, bar);
    // a date label on the first, last and every ~7th slot
    const every = Math.max(1, Math.round(buckets.length / (W < 500 ? 3 : 6)));
    if (i === 0 || i === buckets.length - 1 || i % every === 0) {
      const lab = svg('text', { x: padL + i * slot + slot / 2, y: H - 6, 'text-anchor': 'middle', class: 'axis' });
      lab.textContent = fmt(b.start);
      s.append(lab);
    }
  });
  box.replaceChildren(s, tip);
}

let lastChart = null;
let resizeTimer = 0;
addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => lastChart && !$('views-body').hidden && chart(...lastChart), 150);
});

$('views-refresh').addEventListener('click', refresh);
$('views-days').addEventListener('change', refresh);
$('views-key-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const key = $('views-key').value.trim();
  if (!/^[A-Za-z0-9_-]{16,200}$/.test(key)) return say('That does not look like a read key (copy the long code from the Apps Script log).', 'error');
  if (!ctx?.publicKey) return say('Unlock the page first.', 'error');
  const sealed = b64u(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, ctx.publicKey, text.enc(key)));
  store.set(sealed);
  $('views-key').value = '';
  refresh();
});
