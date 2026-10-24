// The share viewer: password → open the share token → check its expiry against the server's clock and
// the owner's list of switched-off links → hand the project key to the service worker → show the
// project, watermarked with the recipient's name.
import { deleteSession, formatDate, linkId, readShareToken, revokedIds, saveSession, serverNow } from './crypto.js?v=95fc3c7c4d';

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
  const frame = document.createElement('iframe');
  frame.title = share.title;
  frame.allow = 'fullscreen; xr-spatial-tracking';
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
    await deleteSession(share.pid);
    lockOut(`This link for ${share.name} ${reason}. Ask ASTRA DWELL for a new one.`);
  }, 15_000);
}
