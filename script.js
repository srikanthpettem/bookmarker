
(() => {
'use strict';

const STORAGE_KEY = 'sitebook.encrypted.v1';
const ITERATIONS = 600000;
const IDLE_MS = 15 * 60 * 1000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = id => document.getElementById(id);
const icon = id => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.classList.add('icon');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#i-' + id);
    svg.append(use);
    return svg;
};
const element = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
};
const iconButton = (name, label, handler) => {
    const button = element('button', 'icon-button');
    button.type = 'button';
    button.title = label;
    button.setAttribute('aria-label', label);
    button.append(icon(name));
    button.addEventListener('click', handler);
    return button;
};

let vault = null;
let key = null;
let salt = null;
let state = null;
let scope = 'all';
let chosenTag = '';
let editingSite = null;
let editingFolder = null;
let saveQueue = Promise.resolve();
let toastTimer = null;
let lastActivity = Date.now();

function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
}
function base64ToBytes(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4) throw new Error('Invalid backup data.');
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}
function validateVault(candidate) {
    if (!candidate || candidate.app !== 'Sitebook' || candidate.version !== 1 || candidate.kdf !== 'PBKDF2-SHA256' || candidate.cipher !== 'AES-256-GCM' || !Number.isInteger(candidate.iterations) || candidate.iterations < 100000 || candidate.iterations > 5000000) throw new Error('This is not a supported Sitebook backup.');
    if (base64ToBytes(candidate.salt).length !== 16 || base64ToBytes(candidate.iv).length !== 12 || base64ToBytes(candidate.data).length < 17) throw new Error('The backup is incomplete or damaged.');
    return candidate;
}
async function derive(password, savedVault) {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', hash:'SHA-256', salt:base64ToBytes(savedVault.salt), iterations:savedVault.iterations}, material, {name:'AES-GCM', length:256}, false, ['encrypt', 'decrypt']);
}
async function seal(snapshot) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, encoder.encode(snapshot));
    return {app:'Sitebook',version:1,kdf:'PBKDF2-SHA256',cipher:'AES-256-GCM',iterations:vault.iterations,salt:vault.salt,iv:bytesToBase64(iv),data:bytesToBase64(new Uint8Array(ciphertext))};
}
async function openVault(savedVault, password) {
    const newKey = await derive(password, savedVault);
    const plaintext = await crypto.subtle.decrypt({name:'AES-GCM',iv:base64ToBytes(savedVault.iv)}, newKey, base64ToBytes(savedVault.data));
    const next = JSON.parse(decoder.decode(plaintext));
    if (next.version !== 1 || !Array.isArray(next.sites) || !Array.isArray(next.folders) || typeof next.loadIcons !== 'boolean') throw new Error('Unsupported vault content.');
    if (next.sites.some(s => !s || typeof s.id !== 'string' || typeof s.name !== 'string' || typeof s.url !== 'string' || !Array.isArray(s.tags)) || next.folders.some(f => !f || typeof f.id !== 'string' || typeof f.name !== 'string')) throw new Error('Invalid vault content.');
    return {newKey, next};
}
function toast(message, isError = false) {
    const node = $('toast');
    node.textContent = message;
    node.classList.toggle('error', isError);
    node.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.add('hidden'), 3600);
}
function queueSave() {
    if (!state || !key) return;
    const snapshot = JSON.stringify(state);
    $('save-status').textContent = 'Saving…';
    saveQueue = saveQueue.catch(() => {}).then(async () => {
    const encrypted = await seal(snapshot);
    if (localStorage.getItem(STORAGE_KEY) !== JSON.stringify(vault)) throw new Error('This vault changed in another tab.');
    localStorage.setItem(STORAGE_KEY, JSON.stringify(encrypted));
    vault = encrypted;
    $('save-status').textContent = 'Saved on this device';
    }).catch(error => {
    $('save-status').textContent = 'Save failed · export a backup';
    toast('Could not save: ' + error.message + '. Export a backup of the current vault.', true);
    throw error;
    });
}
function showAuth() {
    $('app').classList.add('hidden');
    $('auth-screen').classList.remove('hidden');
    const exists = !!localStorage.getItem(STORAGE_KEY);
    $('auth-title').textContent = exists ? 'Welcome back.' : 'Make room for your links.';
    $('auth-description').textContent = exists ? 'Unlock your collection with your master password.' : 'Keep websites, logins and notes together, organized your way.';
    $('confirm-field').classList.toggle('hidden', exists);
    $('confirm-password').required = !exists;
    $('initial-import').textContent = exists ? 'Import encrypted backup' : 'Import an existing backup';
    $('auth-submit').textContent = exists ? 'Unlock Sitebook' : 'Create my vault';
    $('auth-error').textContent = '';
    $('auth-form').reset();
    $('master-password').focus();
}
function showApp() {
    $('auth-form').reset();
    $('auth-screen').classList.add('hidden');
    $('app').classList.remove('hidden');
    lastActivity = Date.now();
    scope = 'all';
    chosenTag = '';
    $('search').value = '';
    render();
}
async function lock() {
    try { await saveQueue; } catch { /* The export action can still save the current in-memory data. */ }
    $('site-dialog').close();
    $('folder-dialog').close();
    key = null;
    state = null;
    vault = null;
    salt = null;
    $('card-list').replaceChildren();
    showAuth();
}
function normalizedUrl(value) {
    const input = value.trim();
    const parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(input) ? input : 'https://' + input);
    if (!['https:', 'http:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) throw new Error('Enter a valid http:// or https:// website URL.');
    return parsed.href;
}
function folderById(id) { return state.folders.find(folder => folder.id === id); }
function folderPath(id) {
    const path = [];
    const seen = new Set();
    while (id && !seen.has(id)) {
    seen.add(id);
    const folder = folderById(id);
    if (!folder) break;
    path.unshift(folder.name);
    id = folder.parentId;
    }
    return path.join(' / ');
}
function folderIsIn(candidateId, parentId) {
    if (!candidateId || !parentId) return false;
    const seen = new Set();
    let current = candidateId;
    while (current && !seen.has(current)) {
    if (current === parentId) return true;
    seen.add(current);
    current = folderById(current)?.parentId;
    }
    return false;
}
function sortedFolders() {
    const sorted = state.folders.slice().sort((a,b) => a.name.localeCompare(b.name, undefined, {sensitivity:'base'}));
    const result = [];
    const visited = new Set();
    function visit(parentId, depth) {
    for (const folder of sorted.filter(item => item.parentId === parentId)) {
        if (visited.has(folder.id)) continue;
        visited.add(folder.id);
        result.push({folder, depth});
        visit(folder.id, depth + 1);
    }
    }
    visit(null, 0);
    for (const folder of sorted) if (!visited.has(folder.id)) { visited.add(folder.id); result.push({folder, depth:0}); visit(folder.id, 1); }
    return result;
}
function populateFolders(select, selected, excludedId = null) {
    select.replaceChildren(new Option(select.id === 'site-folder' ? 'No folder' : 'Top level', ''));
    for (const {folder, depth} of sortedFolders()) {
    if (excludedId && folderIsIn(folder.id, excludedId)) continue;
    select.add(new Option('　'.repeat(Math.min(depth, 8)) + folder.name, folder.id));
    }
    select.value = selected || '';
}
function renderSidebar() {
    $('all-count').textContent = state.sites.length;
    $('unfiled-count').textContent = state.sites.filter(site => !folderById(site.folderId)).length;
    $('nav-all').classList.toggle('active', scope === 'all');
    $('nav-unfiled').classList.toggle('active', scope === 'unfiled');
    const list = $('folder-list');
    list.replaceChildren();
    const mobile = $('mobile-folder-select');
    mobile.replaceChildren(new Option('All websites', 'all'), new Option('Unfiled', 'unfiled'));
    for (const {folder, depth} of sortedFolders()) {
    const row = element('div', 'folder-row' + (scope === folder.id ? ' active' : ''));
    const open = element('button', 'folder-open');
    open.type = 'button';
    open.style.paddingLeft = (11 + Math.min(depth, 5) * 15) + 'px';
    open.append(icon('folder'), element('span', '', folder.name));
    open.title = folderPath(folder.id);
    open.addEventListener('click', () => {scope = folder.id; render();});
    const manage = iconButton('pencil', 'Edit ' + folder.name, () => openFolderDialog(folder.id));
    manage.classList.add('folder-manage');
    row.append(open, manage);
    list.append(row);
    mobile.add(new Option('　'.repeat(Math.min(depth, 8)) + folder.name, folder.id));
    }
    mobile.value = scope;
    $('edit-folder-mobile').classList.toggle('hidden', !folderById(scope));
    $('load-icons').checked = state.loadIcons;
    $('load-icons-mobile').checked = state.loadIcons;
}
function renderTags() {
    const tags = [...new Set(state.sites.flatMap(site => site.tags).filter(tag => typeof tag === 'string' && tag.trim()))].sort((a,b) => a.localeCompare(b));
    const select = $('tag-filter');
    select.replaceChildren(new Option('All tags', ''));
    for (const tag of tags) select.add(new Option(tag, tag));
    if (!tags.includes(chosenTag)) chosenTag = '';
    select.value = chosenTag;
}
function renderCard(site) {
    const card = element('article', 'card');
    const top = element('div', 'card-top');
    const siteIcon = element('div', 'site-icon', site.name.trim().charAt(0) || '?');
    const customIcon = typeof site.iconData === 'string' && /^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(site.iconData);
    if (customIcon || state.loadIcons) {
    const image = element('img');
    image.alt = '';
    image.referrerPolicy = 'no-referrer';
    image.addEventListener('error', () => {siteIcon.textContent = site.name.trim().charAt(0) || '?';}, {once:true});
    // Saved URLs are checked again before being used as network or link targets.
    try {
        const safeUrl = normalizedUrl(site.url);
        image.src = customIcon ? site.iconData : new URL('/favicon.ico', safeUrl).href;
        siteIcon.replaceChildren(image);
    } catch { /* Keep the local initial when an imported URL is invalid. */ }
    }
    const cardActions = element('div', 'card-actions');
    cardActions.append(iconButton('pencil', 'Edit ' + site.name, () => openSiteDialog(site.id)), iconButton('trash', 'Delete ' + site.name, () => removeSite(site.id)));
    top.append(siteIcon, cardActions);
    const heading = element('h2');
    const link = element('a', '', site.name);
    try { link.href = normalizedUrl(site.url); link.target = '_blank'; link.rel = 'noopener noreferrer'; link.referrerPolicy = 'no-referrer'; }
    catch { link.removeAttribute('href'); }
    heading.append(link);
    let displayUrl = site.url;
    try { const parsed = new URL(site.url); displayUrl = parsed.host + (parsed.pathname === '/' ? '' : parsed.pathname) + parsed.search; }
    catch { /* Keep the input as text. */ }
    const url = element('div', 'site-url', displayUrl);
    url.title = site.url;
    const pills = element('div', 'pills');
    if (folderById(site.folderId)) pills.append(element('span', 'folder-pill', folderPath(site.folderId)));
    for (const tag of site.tags) {
    const pill = element('button', 'tag-pill', tag);
    pill.type = 'button';
    pill.title = 'Filter by ' + tag;
    pill.addEventListener('click', () => { chosenTag = tag; render(); });
    pills.append(pill);
    }
    card.append(top, heading, url, pills);
    if (site.comments) card.append(element('p', 'comment', site.comments));
    card.append(element('div', 'card-spacer'));
    const username = element('div', 'credential');
    username.append(element('span', 'cred-label', 'Username'));
    const usernameText = element('span', 'cred-value', site.username || '—');
    usernameText.title = site.username || '';
    username.append(usernameText);
    const copyUser = iconButton('copy', 'Copy username', () => copyText(site.username, 'Username copied'));
    copyUser.disabled = !site.username;
    username.append(copyUser);
    const password = element('div', 'credential');
    password.append(element('span', 'cred-label', 'Password'));
    const passwordText = element('span', 'cred-value', site.password ? '••••••••' : '—');
    password.append(passwordText);
    const reveal = iconButton('eye', 'Show password', () => {
    if (passwordText.textContent === site.password) { passwordText.textContent = '••••••••'; reveal.title = 'Show password'; reveal.setAttribute('aria-label', 'Show password'); reveal.replaceChildren(icon('eye')); }
    else {
        passwordText.textContent = site.password;
        reveal.title = 'Hide password'; reveal.setAttribute('aria-label', 'Hide password'); reveal.replaceChildren(icon('eye-off'));
        setTimeout(() => {passwordText.textContent = '••••••••'; reveal.title = 'Show password'; reveal.setAttribute('aria-label', 'Show password'); reveal.replaceChildren(icon('eye'));}, 15000);
    }
    });
    reveal.disabled = !site.password;
    const copyPassword = iconButton('copy', 'Copy password', () => copyText(site.password, 'Password copied'));
    copyPassword.disabled = !site.password;
    password.append(reveal, copyPassword);
    card.append(username, password);
    const date = new Date(site.createdAt);
    card.append(element('div', 'card-date', 'Added ' + (Number.isNaN(date.valueOf()) ? 'recently' : new Intl.DateTimeFormat(undefined, {day:'numeric',month:'short',year:'numeric'}).format(date))));
    return card;
}
function render() {
    if (!state) return;
    if (!['all','unfiled'].includes(scope) && !folderById(scope)) scope = 'all';
    renderSidebar();
    renderTags();
    const q = $('search').value.trim().toLocaleLowerCase();
    const filtered = state.sites.filter(site => {
    if (scope === 'unfiled' && folderById(site.folderId)) return false;
    if (scope !== 'all' && scope !== 'unfiled' && !folderIsIn(site.folderId, scope)) return false;
    if (chosenTag && !site.tags.includes(chosenTag)) return false;
    return !q || [site.name,site.url,...site.tags].some(value => String(value).toLocaleLowerCase().includes(q));
    }).sort((a,b) => (Date.parse(b.createdAt) || 0) - (Date.parse(a.createdAt) || 0) || state.sites.indexOf(b) - state.sites.indexOf(a));
    const title = scope === 'all' ? 'All websites' : scope === 'unfiled' ? 'Unfiled' : folderById(scope).name;
    $('page-title').textContent = title;
    $('page-subtitle').textContent = scope === 'all' ? 'All your important places, in one place.' : scope === 'unfiled' ? 'Websites waiting for a folder.' : folderPath(scope);
    $('result-count').textContent = filtered.length + (filtered.length === 1 ? ' website' : ' websites') + (q || chosenTag ? ' found' : ' · newest first');
    $('card-list').replaceChildren(...filtered.map(renderCard));
    const empty = filtered.length === 0;
    $('empty-state').classList.toggle('hidden', !empty);
    $('card-list').classList.toggle('hidden', empty);
    const narrowed = !!q || !!chosenTag || scope !== 'all';
    $('empty-title').textContent = narrowed ? 'Nothing here yet' : 'Your collection starts here';
    $('empty-copy').textContent = narrowed ? 'Try another search or tag, or add a website to this folder.' : 'Add your first website and it will appear here, newest first.';
}
function parseTags(value) {
    const seen = new Set();
    return value.split(',').map(tag => tag.trim()).filter(tag => {
    const normalized = tag.toLocaleLowerCase();
    if (!tag || seen.has(normalized)) return false;
    seen.add(normalized);
    return true;
    }).slice(0, 25);
}
async function readIcon(file) {
    if (!['image/png','image/jpeg','image/webp'].includes(file.type) || file.size > 2 * 1024 * 1024) throw new Error('Choose a PNG, JPG or WebP image smaller than 2 MB.');
    const blobUrl = URL.createObjectURL(file);
    try {
    const image = new Image();
    image.src = blobUrl;
    await image.decode();
    const canvas = document.createElement('canvas');
    canvas.width = 96;
    canvas.height = 96;
    const context = canvas.getContext('2d');
    const scale = Math.min(96 / image.naturalWidth, 96 / image.naturalHeight);
    context.drawImage(image, (96 - image.naturalWidth * scale) / 2, (96 - image.naturalHeight * scale) / 2, image.naturalWidth * scale, image.naturalHeight * scale);
    return canvas.toDataURL('image/png');
    } catch { throw new Error('That image could not be opened.'); }
    finally { URL.revokeObjectURL(blobUrl); }
}
function openSiteDialog(id = null) {
    editingSite = id;
    const site = id ? state.sites.find(item => item.id === id) : null;
    $('site-form').reset();
    $('site-error').textContent = '';
    $('site-dialog-title').textContent = site ? 'Edit website' : 'Add website';
    $('delete-site').classList.toggle('hidden', !site);
    $('remove-icon-row').classList.toggle('hidden', !site?.iconData);
    $('site-name').value = site?.name || '';
    $('site-url').value = site?.url || '';
    $('site-username').value = site?.username || '';
    $('site-password').value = site?.password || '';
    $('site-tags').value = site?.tags.join(', ') || '';
    $('site-comments').value = site?.comments || '';
    populateFolders($('site-folder'), site ? site.folderId : folderById(scope) ? scope : '');
    $('site-dialog').showModal();
    $('site-name').focus();
}
function removeSite(id) {
    const site = state.sites.find(item => item.id === id);
    if (!site || !confirm('Delete "' + site.name + '"? This cannot be undone.')) return;
    state.sites = state.sites.filter(item => item.id !== id);
    $('site-dialog').close();
    queueSave();
    render();
    toast('Website deleted');
}
function openFolderDialog(id = null, requestedParent = null) {
    editingFolder = id;
    const folder = id ? folderById(id) : null;
    $('folder-form').reset();
    $('folder-error').textContent = '';
    $('folder-dialog-title').textContent = folder ? 'Edit folder' : 'New folder';
    $('delete-folder').classList.toggle('hidden', !folder);
    $('folder-name').value = folder?.name || '';
    populateFolders($('folder-parent'), folder ? folder.parentId : requestedParent || (folderById(scope) ? scope : ''), id);
    $('folder-dialog').showModal();
    $('folder-name').focus();
}
function removeFolder() {
    const folder = folderById(editingFolder);
    if (!folder) return;
    if (state.sites.some(site => site.folderId === folder.id) || state.folders.some(item => item.parentId === folder.id)) {
    $('folder-error').textContent = 'Move the websites and subfolders out of this folder before deleting it.';
    return;
    }
    if (!confirm('Delete the empty folder "' + folder.name + '"?')) return;
    state.folders = state.folders.filter(item => item.id !== folder.id);
    if (scope === folder.id) scope = 'all';
    $('folder-dialog').close();
    queueSave();
    render();
    toast('Folder deleted');
}
async function copyText(value, message) {
    try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText(value);
    toast(message);
    } catch {
    const field = element('textarea');
    field.value = value;
    field.style.cssText = 'position:fixed;left:-9999px;top:0';
    document.body.append(field);
    field.select();
    try { if (!document.execCommand('copy')) throw new Error('Copy failed'); toast(message); }
    catch { toast('Copy is unavailable in this browser. Use the Edit button to select the value.', true); }
    finally { field.remove(); }
    }
}
async function exportBackup() {
    if (!state) return;
    try {
    // Export the current in-memory data even if browser storage is full.
    const backup = await seal(JSON.stringify(state));
    const blob = new Blob([JSON.stringify({...backup, exportedAt:new Date().toISOString()}, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const link = element('a');
    link.href = url;
    link.download = 'sitebook-backup-' + new Date().toISOString().slice(0,10) + '.json';
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    toast('Encrypted backup downloaded');
    } catch (error) { toast('Backup failed: ' + error.message, true); }
}
async function importBackup(file) {
    if (!file || file.size > 10 * 1024 * 1024) { toast('Select a backup smaller than 10 MB.', true); return; }
    try {
    const imported = validateVault(JSON.parse(await file.text()));
    const password = prompt('Enter the master password for this backup:');
    if (password === null) return;
    const opened = await openVault(imported, password);
    if (localStorage.getItem(STORAGE_KEY) && !confirm('Replace your current collection with this backup (' + opened.next.sites.length + ' websites)? Export your current collection first if you want to keep it.')) return;
    if (state) try { await saveQueue; } catch { /* The user explicitly chose to replace this collection. */ }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(imported));
    key = opened.newKey;
    vault = imported;
    state = opened.next;
    showApp();
    toast('Backup imported');
    } catch (error) { toast(error.name === 'OperationError' ? 'Incorrect password or damaged backup.' : 'Import failed: ' + error.message, true); }
}

$('auth-form').addEventListener('submit', async event => {
    event.preventDefault();
    const password = $('master-password').value;
    const existing = localStorage.getItem(STORAGE_KEY);
    $('auth-error').textContent = '';
    if (!existing && (password.length < 12 || password !== $('confirm-password').value)) {
    $('auth-error').textContent = password.length < 12 ? 'Use at least 12 characters for your master password.' : 'The passwords do not match.';
    return;
    }
    const submit = $('auth-submit');
    submit.disabled = true;
    submit.textContent = existing ? 'Unlocking…' : 'Creating…';
    try {
    if (existing) {
        vault = validateVault(JSON.parse(existing));
        const opened = await openVault(vault, password);
        key = opened.newKey;
        state = opened.next;
    } else {
        salt = crypto.getRandomValues(new Uint8Array(16));
        vault = {iterations:ITERATIONS,salt:bytesToBase64(salt)};
        key = await derive(password, vault);
        state = {version:1,sites:[],folders:[],loadIcons:true};
        const encrypted = await seal(JSON.stringify(state));
        localStorage.setItem(STORAGE_KEY, JSON.stringify(encrypted));
        vault = encrypted;
    }
    showApp();
    } catch (error) {
    key = null;
    state = null;
    $('auth-error').textContent = existing && error.name === 'OperationError' ? 'Incorrect master password.' : 'Could not open the vault: ' + error.message;
    } finally { submit.disabled = false; submit.textContent = existing ? 'Unlock Sitebook' : 'Create my vault'; }
});
$('site-form').addEventListener('submit', async event => {
    event.preventDefault();
    $('site-error').textContent = '';
    const save = $('save-site');
    save.disabled = true;
    try {
    const name = $('site-name').value.trim();
    if (!name) throw new Error('Enter a website name.');
    const url = normalizedUrl($('site-url').value);
    const existing = editingSite && state.sites.find(item => item.id === editingSite);
    let iconData = $('remove-icon').checked ? '' : existing?.iconData || '';
    if ($('site-icon-file').files[0]) iconData = await readIcon($('site-icon-file').files[0]);
    const site = {id:existing?.id || crypto.randomUUID(),name,url,username:$('site-username').value.trim(),password:$('site-password').value,comments:$('site-comments').value.trim(),tags:parseTags($('site-tags').value),folderId:$('site-folder').value || null,iconData,createdAt:existing?.createdAt || new Date().toISOString()};
    if (existing) state.sites[state.sites.indexOf(existing)] = site;
    else state.sites.push(site);
    $('site-dialog').close();
    queueSave();
    render();
    toast(existing ? 'Website updated' : 'Website added');
    } catch (error) { $('site-error').textContent = error.message; }
    finally { save.disabled = false; }
});
$('folder-form').addEventListener('submit', event => {
    event.preventDefault();
    const name = $('folder-name').value.trim();
    const parentId = $('folder-parent').value || null;
    const existing = editingFolder && folderById(editingFolder);
    if (!name) { $('folder-error').textContent = 'Enter a folder name.'; return; }
    if (state.folders.some(folder => folder.id !== existing?.id && folder.parentId === parentId && folder.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
    $('folder-error').textContent = 'A folder with that name already exists here.';
    return;
    }
    if (existing) { existing.name = name; existing.parentId = parentId; }
    else state.folders.push({id:crypto.randomUUID(),name,parentId,createdAt:new Date().toISOString()});
    $('folder-dialog').close();
    queueSave();
    render();
    toast(existing ? 'Folder updated' : 'Folder created');
});
$('search').addEventListener('input', render);
$('tag-filter').addEventListener('change', event => {chosenTag = event.target.value; render();});
$('nav-all').addEventListener('click', () => {scope = 'all'; render();});
$('nav-unfiled').addEventListener('click', () => {scope = 'unfiled'; render();});
$('mobile-folder-select').addEventListener('change', event => {scope = event.target.value; render();});
for (const id of ['load-icons','load-icons-mobile']) $(id).addEventListener('change', event => {state.loadIcons = event.target.checked; queueSave(); render();});
$('new-site').addEventListener('click', () => openSiteDialog());
$('empty-action').addEventListener('click', () => openSiteDialog());
$('new-folder').addEventListener('click', () => openFolderDialog());
$('new-folder-mobile').addEventListener('click', () => openFolderDialog());
$('edit-folder-mobile').addEventListener('click', () => {if (folderById(scope)) openFolderDialog(scope);});
$('delete-site').addEventListener('click', () => removeSite(editingSite));
$('delete-folder').addEventListener('click', removeFolder);
for (const id of ['close-site','cancel-site']) $(id).addEventListener('click', () => $('site-dialog').close());
for (const id of ['close-folder','cancel-folder']) $(id).addEventListener('click', () => $('folder-dialog').close());
for (const id of ['export-backup','mobile-export']) $(id).addEventListener('click', exportBackup);
for (const id of ['lock-vault','mobile-lock']) $(id).addEventListener('click', lock);
for (const id of ['import-backup','initial-import','mobile-import']) $(id).addEventListener('click', () => $('backup-file').click());
$('backup-file').addEventListener('change', async event => {await importBackup(event.target.files[0]); event.target.value = '';});
document.addEventListener('keydown', event => {
    if (event.key === '/' && state && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName) && !$('site-dialog').open && !$('folder-dialog').open) {event.preventDefault(); $('search').focus();}
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && state) {event.preventDefault(); $('search').focus();}
});
for (const type of ['pointerdown','keydown']) document.addEventListener(type, () => {lastActivity = Date.now();}, {passive:true});
setInterval(() => {if (state && Date.now() - lastActivity >= IDLE_MS) {lock(); toast('Vault locked after 15 minutes of inactivity.');}}, 30000);
window.addEventListener('storage', event => {
    if (event.key === STORAGE_KEY && state && event.newValue !== JSON.stringify(vault)) {
    lock();
    toast('The vault changed in another tab. Unlock to load the latest copy.');
    }
});
try {
    if (!crypto?.subtle || !crypto?.randomUUID) throw new Error('This browser does not provide Web Crypto. Open the file in a current Chrome, Edge, or Firefox browser.');
    localStorage.getItem(STORAGE_KEY);
    showAuth();
} catch (error) {
    $('auth-form').classList.add('hidden');
    $('initial-import').classList.add('hidden');
    $('auth-title').textContent = 'Browser storage unavailable';
    $('auth-description').textContent = error.message + ' If you opened this as a local file, try another current browser or serve this file on localhost.';
}
})();