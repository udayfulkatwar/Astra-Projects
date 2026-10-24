// Owner page: unlocks the owner's RSA key with the passphrase, lists the encrypted projects, and makes
// share links: client name + expiry + password, sealed into the link.
// With a GitHub token (saved once, locked with the owner key) the page also writes to the gh-pages
// branch: revoked.json (switched-off links), owner.json (the owner key, locked by the passphrase, plus
// the GitHub token, locked by the owner key) and links.json (the owner's links, locked by the owner
// key). So any device opens this page with the passphrase alone and shows the same links.
import { OWNER_ITERATIONS, b64u, formatDate, linkId, makeShareToken, open, passwordKey, projectKey, random, readShareToken, seal, serverNow, text, unb64u } from './crypto.js?v=95fc3c7c4d';

const $ = (id) => document.getElementById(id);
const OWNER = 'astra-owner-key';
const HISTORY = 'astra-share-history';
const GITHUB = 'astra-github-key';
const REPO = 'udayfulkatwar/astra-projects';
const OWNER_FILE = 'owner.json';
const LINKS_FILE = 'links.json';
const store = {
  get: (k) => {
    try {
      return localStorage.getItem(k);
    } catch {
      return null;
    }
  },
  set: (k, v) => {
    try {
      localStorage.setItem(k, v);
      return true;
    } catch {
      return false;
    }
  },
  del: (k) => {
    try {
      localStorage.removeItem(k);
    } catch {
      // nothing saved
    }
  },
};

let ownerFile = JSON.parse(store.get(OWNER) || 'null');
let privateKey = null;
let projects = [];
let current = null;
let githubToken = null;
let serverOwner = null; // owner.json as the portal serves it (null: none yet)
let mainKey = null; // public key of the main owner key (owner-public.json): the only one accepted
const isMain = (file) => Boolean(file) && (!mainKey || file.publicKey === mainKey);

let statusTimer;
const status = (msg, kind = '') => {
  clearTimeout(statusTimer);
  $('status').textContent = msg;
  $('status').className = `toast ${kind}`;
  if (kind === 'ok') statusTimer = setTimeout(() => ($('status').textContent = ''), 10_000);
};
$('status').addEventListener('click', () => status('')); // tap a message to close it
const showOnly = (...ids) => {
  for (const id of ['setup', 'waiting', 'public', 'unlock', 'projects']) $(id).hidden = !ids.includes(id);
};

async function copy(value, label) {
  try {
    await navigator.clipboard.writeText(value);
    status(`${label} copied.`, 'ok');
  } catch {
    status(`Copy didn't work here: select the ${label.toLowerCase()} and copy it by hand.`, 'error');
  }
}

function download(name, data) {
  const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const backup = () => download('astra-owner-key-backup.json', JSON.stringify(ownerFile, null, 2));

// ---- owner key -----------------------------------------------------------------------------------

async function createOwnerKey(passphrase) {
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const salt = random(16);
  const sealed = await seal(await passwordKey(passphrase, salt, OWNER_ITERATIONS), pkcs8, 'astra-owner-v1');
  return { v: 1, kind: 'astra-owner-key', salt: b64u(salt), iterations: OWNER_ITERATIONS, key: b64u(sealed), publicKey: b64u(spki) };
}

async function unlockOwnerKey(file, passphrase) {
  const pkcs8 = await open(await passwordKey(passphrase, unb64u(file.salt), file.iterations), unb64u(file.key), 'astra-owner-v1');
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

const ownerCore = (f) => ({ v: 1, kind: 'astra-owner-key', salt: f.salt, iterations: f.iterations, key: f.key, publicKey: f.publicKey });

/** A file the portal serves; null when it is not there. Throws when the portal cannot be reached. */
async function siteJson(name) {
  const res = await fetch(`/${name}?t=${Date.now()}`, { cache: 'no-store' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${name} ${res.status}`);
  return res.json();
}

function showPublicKey() {
  $('public-key').textContent = ownerFile.publicKey;
  showOnly('public');
}

$('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const a = $('setup-pass').value;
  if (a.length < 12) return status('Use at least 12 characters for the passphrase.', 'error');
  if (a !== $('setup-pass2').value) return status('The two passphrases are different.', 'error');
  status('Creating your key…');
  ownerFile = await createOwnerKey(a);
  if (!store.set(OWNER, JSON.stringify(ownerFile))) status('This browser would not save the key: download the backup now and keep it.', 'error');
  else status('Owner key created.', 'ok');
  privateKey = await unlockOwnerKey(ownerFile, a);
  $('setup-pass').value = $('setup-pass2').value = '';
  showPublicKey();
});

$('import-file').addEventListener('change', async () => {
  const file = $('import-file').files[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    if (data.kind !== 'astra-owner-key' || !data.key || !data.publicKey) throw new Error('not a key');
    if (!isMain(data)) return status('That backup is a different owner key, not the main one the projects are locked for.', 'error');
    ownerFile = ownerCore(data);
    store.set(OWNER, JSON.stringify(ownerFile));
    status('Key backup imported. Unlock it with your passphrase.', 'ok');
    showOnly('unlock');
  } catch {
    status('That file is not an ASTRA DWELL key backup.', 'error');
  }
});

$('waiting-reload').addEventListener('click', () => location.reload());
$('copy-public').addEventListener('click', () => copy(ownerFile.publicKey, 'Public key'));
$('download-backup').addEventListener('click', backup);
$('backup').addEventListener('click', backup);
$('show-public').addEventListener('click', showPublicKey);
$('public-done').addEventListener('click', () => (privateKey ? loadProjects() : showOnly('unlock')));
$('lock').addEventListener('click', () => {
  privateKey = null;
  githubToken = null;
  projects = [];
  status('Locked.');
  showOnly('unlock');
});

$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  status('Unlocking…');
  try {
    privateKey = await unlockOwnerKey(ownerFile, $('unlock-pass').value);
  } catch {
    return status('That passphrase does not open this key.', 'error');
  }
  $('unlock-pass').value = '';
  status('');
  loadProjects();
});

// ---- projects -------------------------------------------------------------------------------------

async function loadProjects() {
  showOnly('projects');
  renderHistory();
  $('project-list').replaceChildren();
  let ids = [];
  try {
    ids = (await (await fetch('/catalog.json', { cache: 'no-store' })).json()).projects || [];
  } catch {
    ids = [];
  }
  projects = [];
  for (const pid of ids) {
    try {
      const wrapped = (await (await fetch(`/p/${pid}/key.json`, { cache: 'no-store' })).json()).wrapped;
      const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64u(wrapped)));
      const meta = JSON.parse(text.dec(await open(await projectKey(raw), new Uint8Array(await (await fetch(`/p/${pid}/meta.bin`, { cache: 'no-store' })).arrayBuffer()), `${pid}/meta`)));
      projects.push({ pid, raw, ...meta });
    } catch {
      // Locked for a different owner key: not shown.
    }
  }
  $('no-projects').hidden = projects.length > 0;
  for (const p of projects) {
    const li = document.createElement('li');
    const info = document.createElement('div');
    const h = Object.assign(document.createElement('h2'), { textContent: p.title });
    const d = Object.assign(document.createElement('p'), { className: 'small', textContent: p.description || '' });
    info.append(h, d);
    const btn = Object.assign(document.createElement('button'), { type: 'button', className: 'primary', textContent: 'Create link' });
    btn.addEventListener('click', () => startShare(p));
    li.append(info, btn);
    $('project-list').append(li);
  }
  await syncOwner();
  await syncLinks();
}

// Four short words and two digits: easy to read out, hard to guess.
const WORDS = 'amber anchor apple arch atlas autumn bamboo basil beach birch bloom breeze brick bridge brook cabin cactus canal candle canyon cedar chalk cherry cliff cloud clover cobalt comet copper coral cotton crane creek crystal dawn delta desert dune eagle ember fable falcon fern field flint forest frost garden garnet glade glass granite grove harbor hazel heron hill honey horizon iris island ivory jade jasmine juniper kettle kite lagoon lake lantern lark laurel lemon lily linen lotus maple marble meadow mesa mint mist moon moss nectar north oak oasis ocean olive onyx opal orbit orchid otter palm pearl pebble pine planet plaza pond poppy prairie quartz quill rain raven reef ridge river robin rose ruby saffron sage sail sand sapphire shore silk silver sky slate snow solar sparrow spring spruce star stone stream summit sun swan teak thunder tide timber topaz tower trail tulip valley velvet violet walnut wave willow wind winter wren zephyr'.split(' ');
function newPassword() {
  const n = random(5);
  const words = Array.from(n.slice(0, 4), (b) => WORDS[b % WORDS.length]);
  return `${words.join('-')}-${String(10 + (n[4] % 90))}`;
}

function startShare(p) {
  current = p;
  $('share-project').textContent = p.title;
  $('share-name').value = '';
  $('share-pass').value = newPassword();
  $('share-result').hidden = true;
  $('share-form').hidden = false;
  $('share-name').focus();
}

$('new-pass').addEventListener('click', () => ($('share-pass').value = newPassword()));
$('share-cancel').addEventListener('click', () => ($('share-form').hidden = true));

$('share-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = $('share-name').value.trim();
  const password = $('share-pass').value.trim();
  if (!name) return status("Enter the client's name: it is shown on the preview.", 'error');
  if (password.length < 8) return status('Use a password of at least 8 characters.', 'error');
  status('Creating the link…');
  const now = await serverNow();
  const expires = now + Number($('share-days').value) * 60_000; // the select holds minutes
  const created = Date.now(); // with the project, identifies the link when it is switched off
  const token = await makeShareToken({ pid: current.pid, title: current.title, name, expires, created, key: current.raw }, password);
  const link = `${location.origin}/v/#${token}`;
  const until = formatDate(expires);
  $('out-link').textContent = link;
  $('out-pass').textContent = password;
  $('out-until').textContent = `Works until ${until}.`;
  $('share-result').hidden = false;
  const message = `Hello ${name},\n\nHere is your private preview of ${current.title} by ASTRA DWELL:\n${link}\n\nPassword: ${password}\nThe link works until ${until}. It is for you only, please don't forward it.\n\nASTRA DWELL`;
  $('copy-link').onclick = () => copy(link, 'Link');
  $('copy-pass').onclick = () => copy(password, 'Password');
  $('copy-message').onclick = () => copy(message, 'Message');
  writeHistory(mergeLinks([{ name, title: current.title, pid: current.pid, created, expires, link, password }], readHistory()));
  status('Link created.', 'ok');
  syncLinks();
});

// ---- your links (this device, synced through links.json) -------------------------------------------

function readHistory() {
  try {
    return JSON.parse(store.get(HISTORY) || '[]');
  } catch {
    return [];
  }
}

function writeHistory(list) {
  store.set(HISTORY, JSON.stringify(list));
  renderHistory();
}

/** One row per link, newest first; switched off / removed on any device stays so. */
function mergeLinks(...lists) {
  const byLink = new Map();
  for (const list of lists) {
    for (const h of list || []) {
      const old = byLink.get(h.link);
      if (!old) byLink.set(h.link, { ...h });
      else byLink.set(h.link, { ...old, ...h, revoked: Math.max(old.revoked || 0, h.revoked || 0) || undefined, hidden: Math.max(old.hidden || 0, h.hidden || 0) || undefined });
    }
  }
  return [...byLink.values()].sort((a, b) => b.created - a.created).slice(0, 300);
}

async function ownerPublicKey() {
  return crypto.subtle.importKey('spki', unb64u(ownerFile.publicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

async function sealLinks(list) {
  const raw = random(32);
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  return { v: 1, wrapped: b64u(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, await ownerPublicKey(), raw)), data: b64u(await seal(key, text.enc(JSON.stringify(list)), 'astra-links-v1')) };
}

async function openLinks(file) {
  const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64u(file.wrapped)));
  return JSON.parse(text.dec(await open(await projectKey(raw), unb64u(file.data), 'astra-links-v1')));
}

// Merges this device's links with the portal's copy, both ways. One sync at a time.
let syncing = Promise.resolve();
function syncLinks() {
  syncing = syncing.then(async () => {
    if (!privateKey) return;
    try {
      if (!githubToken) {
        const file = await siteJson(LINKS_FILE);
        if (file) writeHistory(mergeLinks(await openLinks(file), readHistory()));
        return;
      }
      await updateRepoFile(LINKS_FILE, 'Owner links', async (file) => {
        const remote = file ? mergeLinks(await openLinks(file)) : [];
        const next = mergeLinks(remote, readHistory());
        writeHistory(next);
        return file && JSON.stringify(remote) === JSON.stringify(next) ? null : sealLinks(next);
      });
    } catch (error) {
      status(`Your links are saved on this device but could not be synced to your other devices: ${error.message}`, 'error');
    }
  });
  return syncing;
}

function renderHistory() {
  const body = $('history');
  body.replaceChildren();
  for (const h of readHistory().filter((row) => !row.hidden)) {
    const tr = document.createElement('tr');
    const expired = Date.now() > h.expires;
    for (const value of [h.name, h.title, `${formatDate(h.expires)}${h.revoked ? ' (switched off)' : expired ? ' (expired)' : ''}`]) tr.append(Object.assign(document.createElement('td'), { textContent: value }));
    const actions = document.createElement('td');
    const copyBtn = Object.assign(document.createElement('button'), { type: 'button', textContent: 'Copy link' });
    copyBtn.addEventListener('click', () => copy(h.link, 'Link'));
    const passBtn = Object.assign(document.createElement('button'), { type: 'button', textContent: 'Copy password' });
    passBtn.addEventListener('click', () => copy(h.password, 'Password'));
    const action = Object.assign(document.createElement('button'), { type: 'button', textContent: h.revoked || expired ? 'Remove' : 'Switch off' });
    action.addEventListener('click', () => (h.revoked || expired ? updateHistory(h.link, null) : switchOffRow(h, action)));
    actions.className = 'row';
    actions.append(copyBtn, passBtn, action);
    tr.append(actions);
    body.append(tr);
  }
}

/** Changes the row for a link (the list may have changed since it was drawn); null removes it from view. */
function updateHistory(link, change) {
  const history = readHistory();
  const row = history.find((h) => h.link === link);
  if (!row) return;
  Object.assign(row, change || { hidden: Date.now() });
  writeHistory(history);
  syncLinks();
}

// ---- GitHub key, and the owner key on the portal -----------------------------------------------------

/** The sealed GitHub token saved on this device: { sealed, at } (older pages saved just the sealed text). */
function localGithub() {
  const raw = store.get(GITHUB);
  if (!raw) return null;
  try {
    const value = JSON.parse(raw);
    if (value && value.sealed) return value;
  } catch {
    // older format
  }
  return { sealed: raw, at: 0 };
}

async function unsealToken(sealed) {
  try {
    return text.dec(new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64u(sealed))));
  } catch {
    return null; // locked for a different owner key
  }
}

function showGithubState() {
  $('gh-state').textContent = githubToken ? 'GitHub key saved: links can be switched off, and this page opens on your other devices with your passphrase alone.' : 'No GitHub key yet: add one below to switch links off and to use this page on your other devices.';
  $('gh-state').className = `small ${githubToken ? 'ok' : 'error'}`;
  $('gh-banner').hidden = Boolean(githubToken);
}

// After unlocking: use the newest GitHub key (this device's or the portal's), and keep the portal's
// copy of the owner key and GitHub key current, so other devices need only the passphrase.
async function syncOwner() {
  try {
    serverOwner = await siteJson(OWNER_FILE);
  } catch {
    // keep what was read at start
  }
  const mine = serverOwner && serverOwner.publicKey === ownerFile.publicKey;
  const remote = mine && 'githubAt' in serverOwner ? { sealed: serverOwner.github || null, at: serverOwner.githubAt || 0 } : null;
  let chosen = localGithub();
  if (remote && (!chosen || remote.at > chosen.at)) {
    chosen = remote.sealed ? remote : null;
    if (chosen) store.set(GITHUB, JSON.stringify(chosen));
    else store.del(GITHUB);
  }
  githubToken = chosen ? await unsealToken(chosen.sealed) : null;
  showGithubState();
  // Only the main key, which opens the projects, goes up, and only when the portal's copy differs.
  if (!githubToken || !projects.length || !isMain(ownerFile)) return;
  if (mine && serverOwner.key === ownerFile.key && serverOwner.github === chosen.sealed && serverOwner.githubAt === chosen.at) return;
  await publishOwner({ github: chosen.sealed, githubAt: chosen.at });
}

async function publishOwner(github) {
  if (!isMain(ownerFile)) return;
  try {
    serverOwner = await updateRepoFile(OWNER_FILE, 'Owner key for the admin page', () => ({ ...ownerCore(ownerFile), ...github }));
  } catch (error) {
    status(`Your other devices could not be updated: ${error.message}`, 'error');
  }
}

function showKeyCard() {
  const card = $('gh-form');
  card.classList.add('highlight');
  card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  $('gh-token').focus({ preventScroll: true });
  setTimeout(() => card.classList.remove('highlight'), 4000);
}
$('gh-setup').addEventListener('click', showKeyCard);

$('gh-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const token = $('gh-token').value.trim();
  if (!token || token.length > 300) return status('Paste the GitHub token first.', 'error');
  status('Checking the GitHub key…');
  const res = await fetch(`https://api.github.com/repos/${REPO}`, { cache: 'no-store', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } }).catch(() => null);
  if (!res) return status('GitHub could not be reached. Check the internet connection and try again.', 'error');
  if (!res.ok) return status(res.status === 401 ? 'GitHub did not accept that token. Copy it again and paste it here.' : `That token cannot see ${REPO} (GitHub answered ${res.status}).`, 'error');
  const saved = { sealed: b64u(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, await ownerPublicKey(), text.enc(token))), at: Date.now() };
  store.set(GITHUB, JSON.stringify(saved));
  githubToken = token;
  $('gh-token').value = '';
  showGithubState();
  status('GitHub key saved, locked with your owner key.', 'ok');
  if (projects.length) await publishOwner({ github: saved.sealed, githubAt: saved.at });
  syncLinks();
});

$('gh-forget').addEventListener('click', async () => {
  // Forget it everywhere: the portal's copy too, or the other devices would bring it back.
  if (githubToken && projects.length) await publishOwner({ github: null, githubAt: Date.now() });
  store.del(GITHUB);
  githubToken = null;
  showGithubState();
  status('GitHub key removed.');
});

const toBase64 = (str) => {
  const s = b64u(text.enc(str)).replace(/-/g, '+').replace(/_/g, '/');
  return s + '==='.slice((s.length + 3) % 4);
};

async function github(file, method, body) {
  const url = `https://api.github.com/repos/${REPO}/contents/${file}${method === 'GET' ? '?ref=gh-pages' : ''}`;
  const headers = { Authorization: `Bearer ${githubToken}`, Accept: 'application/vnd.github+json', ...(body && { 'Content-Type': 'application/json' }) };
  const res = await fetch(url, { method, cache: 'no-store', headers, body: body && JSON.stringify(body) }).catch(() => null);
  if (!res) throw new Error('GitHub could not be reached. Check the internet connection and try again.');
  if (res.status === 401) throw new Error('GitHub no longer accepts the saved key (it may have expired). Save a new one at the bottom of this page.');
  return res;
}

/**
 * Reads a JSON file on gh-pages, lets change() return the new content (or null for no change) and
 * writes it back; reads again when someone else changed it in between. GitHub Pages serves the new
 * file about a minute later.
 */
async function updateRepoFile(file, message, change) {
  if (!githubToken) throw new Error('Switching off needs the GitHub key first (bottom of this page).');
  for (let attempt = 0; attempt < 3; attempt++) {
    const got = await github(file, 'GET');
    if (!got.ok && got.status !== 404) throw new Error(`GitHub answered ${got.status} while reading ${file}. Try again.`);
    const current = got.ok ? await got.json() : null;
    const data = current ? JSON.parse(text.dec(unb64u(current.content.replace(/\s|=/g, '')))) : null;
    const next = await change(data);
    if (next === null) return data;
    const put = await github(file, 'PUT', { message, branch: 'gh-pages', content: toBase64(`${JSON.stringify(next)}\n`), ...(current && { sha: current.sha }) });
    if (put.ok) return next;
    if (put.status === 403 || put.status === 404) throw new Error(`The saved GitHub key cannot change ${REPO}. Make one with Contents: Read and write for that repository.`);
    // 409 / 422: the file changed in between (another device, or a publish): read it again.
  }
  throw new Error(`${file} kept changing on GitHub. Try again.`);
}

// ---- switching links off -------------------------------------------------------------------------------

async function switchOff(id) {
  await updateRepoFile('revoked.json', 'Switch off a preview link', (data) => {
    const ids = (data && data.revoked) || [];
    return ids.includes(id) ? null : { v: 1, revoked: [...ids, id] };
  });
}

// Two taps instead of confirm(), which some in-app browsers block without showing anything.
function secondTap(button, question) {
  if (button.dataset.armed) {
    clearTimeout(Number(button.dataset.armed));
    delete button.dataset.armed;
    button.textContent = button.dataset.label;
    button.classList.remove('danger');
    return true;
  }
  button.dataset.label = button.textContent;
  button.textContent = question;
  button.classList.add('danger');
  button.dataset.armed = String(setTimeout(() => {
    delete button.dataset.armed;
    button.textContent = button.dataset.label;
    button.classList.remove('danger');
  }, 6000));
  return false;
}

// Without a GitHub key: point at the key card, and give the link's code so someone who can publish
// the portal can switch it off instead.
async function needKey(share) {
  const code = share ? ` Or send this switch-off code to whoever publishes the portal: ${await linkId(share.pid, share.created)}` : '';
  status(`Switching off needs the GitHub key first (highlighted below).${code}`, 'error');
  showKeyCard();
}

async function switchOffShare(share, link) {
  status('Switching the link off…');
  try {
    await switchOff(await linkId(share.pid, share.created));
  } catch (error) {
    return status(error.message, 'error');
  }
  updateHistory(link, { revoked: Date.now() });
  status(`${share.name}'s link to ${share.title} is switched off. It stops opening within a few minutes, and an open preview closes by itself.`, 'ok');
}

async function switchOffRow(h, button) {
  let share;
  try {
    share = await readShareToken(new URL(h.link).hash.slice(1), h.password);
  } catch {
    return status("This row's link could not be read. Use “Switch off a link” below with the link and its password.", 'error');
  }
  if (!githubToken) return needKey(share);
  if (!secondTap(button, 'Tap again to switch off')) return status(`Tap again to switch off ${share.name}'s link to ${share.title}. This cannot be undone (you can always make a new link).`);
  await switchOffShare(share, h.link);
}

$('off-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const link = $('off-link').value.trim();
  let share;
  try {
    share = await readShareToken(link.slice(link.indexOf('#') + 1), $('off-pass').value.trim());
  } catch {
    return status('That link and password do not match. Paste the whole link (with the part after #) and its password.', 'error');
  }
  if (!githubToken) return needKey(share);
  if (!secondTap(event.submitter || $('off-form').querySelector('button[type=submit]'), 'Tap again to switch off')) return status(`Tap again to switch off ${share.name}'s link to ${share.title}. This cannot be undone.`);
  await switchOffShare(share, link);
  if ($('status').classList.contains('ok')) $('off-link').value = $('off-pass').value = '';
});

// ---- start ----------------------------------------------------------------------------------------
// Only the main owner key (owner-public.json, the one the projects are locked for) is used. Its copy on
// the portal (owner.json) lets any device unlock with the passphrase; until it is there, a device
// without the main key waits for it instead of making a second key.
async function start() {
  if (!window.isSecureContext || !crypto.subtle) return status('Open this page over https (projects.astragrp.net) to use it.', 'error');
  try {
    mainKey = (await siteJson('owner-public.json'))?.publicKey || null;
    serverOwner = await siteJson(OWNER_FILE);
  } catch {
    return status('The portal could not be reached. Check the internet connection and reload this page.', 'error');
  }
  const server = serverOwner && serverOwner.kind === 'astra-owner-key' && serverOwner.key && isMain(serverOwner) ? serverOwner : null;
  if (ownerFile && !isMain(ownerFile)) {
    // A key made on this device by mistake: set aside (not deleted), never used.
    store.set(`${OWNER}-set-aside`, JSON.stringify(ownerFile));
    store.del(OWNER);
    ownerFile = null;
  }
  if (server && (!ownerFile || ownerFile.key !== server.key)) {
    ownerFile = ownerCore(server);
    store.set(OWNER, JSON.stringify(ownerFile));
  }
  if (ownerFile) return showOnly('unlock');
  if (mainKey) return showOnly('waiting');
  showOnly('setup');
}
start();
