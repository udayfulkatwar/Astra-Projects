// The share viewer: password → open the share token → check its expiry against the server's clock and
// the owner's list of switched-off links → hand the project key to the service worker → show the
// project, watermarked with the recipient's name.
import { LOG_URL } from './config.js?v=166e6947fa';
import { deleteSession, formatDate, linkId, linkRef, readShareToken, revokedIds, saveSession, serverNow } from './crypto.js?v=166e6947fa';

// Never inside another site's frame (clickjacking): GitHub Pages cannot send frame-ancestors.
if (window.top !== window.self) {
  document.documentElement.replaceChildren();
  throw new Error('framed');
}

/**
 * Optional open log (off unless the owner set a log address at build time, see projects-portal/README):
 * open / still-open / closed / wrong-password events go to the owner's Google Sheet: the link's
 * reference, the project, the client's name, a random id for this viewing, the seconds the preview was
 * on screen and a coarse device type. Nothing else.
 */
function device() {
  const ua = navigator.userAgent;
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'other';
  const br = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'other';
  return `${br} on ${os}`;
}
function logEvent(event, fields = {}) {
  if (!LOG_URL) return;
  try {
    navigator.sendBeacon(LOG_URL, new Blob([JSON.stringify({ event, at: new Date().toISOString(), device: device(), ...fields })], { type: 'text/plain' }));
  } catch {
    // logging never blocks the preview
  }
}
async function tokenTag() {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(location.hash.slice(1))));
  return Array.from(hash.slice(0, 6), (b) => b.toString(16).padStart(2, '0')).join('');
}
if (LOG_URL) {
  const note = document.createElement('p');
  note.className = 'small';
  note.textContent = 'For your security, viewing this preview is recorded (when, for how long, link reference and device type).';
  document.getElementById('unlock')?.append(note);
}

const $ = (id) => document.getElementById(id);
const token = location.hash.slice(1);
const form = $('unlock');
const message = $('message');

function say(text, kind = '') {
  message.textContent = text;
  message.className = `small ${kind}`;
}

function lockOut(text) {
  $('title').textContent = 'Preview closed';
  $('intro').textContent = text;
  $('password').closest('label').hidden = true;
  $('submit').hidden = true;
  $('gate').hidden = false;
  $('stage').hidden = true;
  $('stage').replaceChildren();
}

if (!token) {
  lockOut('Open the full link you were sent: it ends with a long code after the # sign.');
} else if (!('serviceWorker' in navigator) || !window.isSecureContext) {
  lockOut('This browser cannot open private previews. Please use a recent version of Chrome, Safari, Edge or Firefox.');
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('password').value.trim();
  if (!password) return say('Enter the password that came with your link.', 'error');
  $('submit').disabled = true;
  say('Checking…');
  let share;
  try {
    share = await readShareToken(token, password);
  } catch {
    $('submit').disabled = false;
    tokenTag().then((tag) => logEvent('wrong-password', { tag }), () => {});
    return say('That password does not match this link. Check it and try again.', 'error');
  }
  const now = await serverNow();
  if (now > share.expires) {
    await deleteSession(share.pid);
    return lockOut(`This link for ${share.name} expired on ${formatDate(share.expires)}. Ask ASTRA DWELL for a new one.`);
  }
  const id = await linkId(share.pid, share.created);
  let off;
  try {
    off = (await revokedIds()).has(id);
  } catch {
    $('submit').disabled = false;
    return say('The link could not be checked just now. Please try again in a moment.', 'error');
  }
  if (off) {
    await deleteSession(share.pid);
    return lockOut(`This link for ${share.name} was switched off. Ask ASTRA DWELL for a new one.`);
  }
  try {
    await saveSession({ pid: share.pid, key: share.key, name: share.name, title: share.title, expires: share.expires, created: share.created, offset: now - Date.now() });
    await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    const ready = await navigator.serviceWorker.ready;
    ready.active?.postMessage({ type: 'forget', pid: share.pid });
  } catch {
    $('submit').disabled = false;
    return say('This browser blocked the preview (private mode can do this). Please try a normal window.', 'error');
  }
  $('password').value = '';
  show(share, id, now - Date.now());
});

function show(share, id, offset) {
  document.title = `${share.title} · Private preview · ASTRA DWELL`;
  // one viewing: a random id, the seconds the preview is actually on screen (only while the tab is
  // visible), a heartbeat every minute and a last report when the page is left
  const sid = Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join('');
  const who = { pid: share.pid, title: share.title, ref: linkRef(id), name: share.name, sid };
  // seconds on screen, measured with the clock (timers can be delayed on a busy device)
  let shown = 0;
  let since = document.visibilityState === 'visible' ? performance.now() : null;
  const secs = () => Math.round((shown + (since === null ? 0 : performance.now() - since)) / 1000);
  let closed = false;
  logEvent('open', { ...who, secs: 0 });
  const beat = setInterval(() => logEvent('still-open', { ...who, secs: secs() }), 60_000);
  const close = () => {
    if (closed) return;
    closed = true;
    logEvent('closed', { ...who, secs: secs() });
  };
  addEventListener('pagehide', close);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      if (since !== null) shown += performance.now() - since;
      since = null;
      if (!closed) logEvent('still-open', { ...who, secs: secs() });
    } else if (since === null) since = performance.now();
  });
  const frame = document.createElement('iframe');
  frame.title = share.title;
  frame.allow = 'fullscreen; xr-spatial-tracking';
  // the app may run scripts and use this site's storage, but cannot navigate the page or submit forms.
  // It may open a link in a new tab (the shop links: amazon.in / the client's own supplier), and that
  // tab leaves the sandbox so the shop works normally; the links carry rel=noopener, so the new tab gets
  // no handle back to this page.
  frame.setAttribute('sandbox', 'allow-scripts allow-same-origin allow-pointer-lock allow-downloads allow-modals allow-popups allow-popups-to-escape-sandbox');
  frame.src = `/x/${share.pid}/index.html`;
  $('stage').replaceChildren(frame);
  $('stage').hidden = false;
  $('gate').hidden = true;
  // Close the preview the moment the link expires, or within a minute of it being switched off, even
  // if the page stays open.
  let ticks = 0;
  const timer = setInterval(async () => {
    let reason = '';
    if (Date.now() + offset > share.expires) reason = `expired on ${formatDate(share.expires)}`;
    else if (++ticks % 4 === 0) reason = await revokedIds().then((ids) => (ids.has(id) ? 'was switched off' : ''), () => '');
    if (!reason) return;
    clearInterval(timer);
    clearInterval(beat);
    close();
    await deleteSession(share.pid);
    lockOut(`This link for ${share.name} ${reason}. Ask ASTRA DWELL for a new one.`);
  }, 15_000);
}
