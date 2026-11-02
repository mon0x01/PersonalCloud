const $ = (id) => document.getElementById(id);
let toastTimer;
let localFiles = [];
let localFolders = [];
let remoteFiles = [];
let selectedRemotePeer = "";
let mfaEnabled = false;
let storageRevision = null;
let statusPollBusy = false;

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}
function bytes(value) {
  const n = Number(value || 0);
  if (n < 1024) return `${n} B`;
  const units = ['KB','MB','GB','TB'];
  let size = n / 1024, i = 0;
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[i]}`;
}
function date(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}
function notify(message, error = false) {
  const box = $('toast');
  box.textContent = message;
  box.className = `toast show${error ? ' error' : ''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.className = 'toast', 3800);
}
async function api(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const contentType = response.headers.get('content-type') || '';
  if (!response.ok) {
    if (response.status === 401 && url !== '/api/auth/login') showAuthScreen();
    let message = `Request failed (${response.status})`;
    if (contentType.includes('application/json')) {
      const body = await response.json().catch(() => ({}));
      message = body.error || message;
    }
    throw new Error(message);
  }
  if (contentType.includes('application/json')) return response.json();
  return response;
}
function formBody(values) {
  return new URLSearchParams(values).toString();
}

function showAuthScreen() {
  $('auth-screen').classList.remove('hidden');
  $('login-code-wrap').classList.toggle('hidden', !mfaEnabled);
  $('login-password').focus();
}
function hideAuthScreen() { $('auth-screen').classList.add('hidden'); }

async function bootstrapAuth() {
  try {
    const status = await api('/api/auth/status');
    mfaEnabled = Boolean(status.mfaEnabled);
    if (!status.authenticated) { showAuthScreen(); return; }
    hideAuthScreen();
    await refreshAll();
  } catch (e) { showAuthScreen(); notify(e.message, true); }
}

async function refreshMfa() {
  const status = await api('/api/mfa/status');
  mfaEnabled = Boolean(status.enabled);
  $('mfa-status').textContent = status.enabled ? `Enabled · ${status.remainingRecoveryCodes} recovery codes remain` : 'Disabled';
  $('setup-mfa').classList.toggle('hidden', status.enabled);
  $('disable-mfa-form').classList.toggle('hidden', !status.enabled);
}

async function refreshStatus() {
  const status = await api('/api/status');
  const nextRevision = Number(status.storageRevision ?? 0);
  const storageChanged = storageRevision !== null && nextRevision !== storageRevision;
  storageRevision = nextRevision;
  $('node-name').textContent = status.nodeName;
  $('node-id-short').textContent = status.nodeId.slice(0, 8);
  $('footer-node').textContent = `Node ${status.nodeId}`;
  $('storage-root').textContent = status.storageRoot;
  $('storage-note').textContent = status.tlsEnabled
    ? `HTTPS enabled · Maximum upload ${bytes(status.maxUploadBytes)}`
    : 'Loopback-only HTTP · Enable TLS before binding this node to a network interface.';
  if (storageChanged) await Promise.all([refreshFiles(), refreshFolders()]);
}

async function refreshFiles() {
  const data = await api('/api/files');
  localFiles = data.files || [];
  $('metric-files').textContent = localFiles.length;
  renderLocalFiles();
}
async function refreshFolders() {
  const data = await api('/api/folders');
  localFolders = data.folders || [];
  renderFolders();
}
function renderFolders() {
  if (!localFolders.length) {
    $('folders-body').innerHTML = '<tr><td colspan="2" class="empty">No folders found. Create one or upload a folder.</td></tr>';
    return;
  }
  $('folders-body').innerHTML = localFolders.map(folder => `<tr>
    <td><div class="file-name">${esc(folder.name)}</div><div class="file-sub">${esc(folder.path)}</div></td>
    <td class="file-actions"><button class="small-action share-folder" data-path="${esc(folder.path)}">Share folder</button><button class="small-action move-folder" data-path="${esc(folder.path)}">Move / rename</button></td>
  </tr>`).join('');
  document.querySelectorAll('.share-folder').forEach(button => button.addEventListener('click', () => {
    $('share-path').value = button.dataset.path;
    $('share-form').scrollIntoView({behavior: 'smooth', block: 'center'});
    $('share-permission').focus();
    notify(`Folder selected: ${button.dataset.path}. Choose a device and permission.`);
  }));
  document.querySelectorAll('.move-folder').forEach(button => button.addEventListener('click', async () => {
    const source = button.dataset.path;
    const destination = prompt('New relative folder path (move or rename):', source);
    if (!destination || destination === source) return;
    try {
      await api('/api/files/move', {method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({source, destination})});
      notify('Folder moved. Existing grants were updated.');
      await Promise.all([refreshFiles(), refreshFolders(), refreshGrants()]);
    } catch (e) { notify(e.message, true); }
  }));
}
function renderLocalFiles() {
  const term = ($('file-search').value || '').toLowerCase();
  const files = localFiles.filter(file => `${file.name} ${file.path}`.toLowerCase().includes(term));
  if (!files.length) {
    $('files-body').innerHTML = `<tr><td colspan="4" class="empty">${localFiles.length ? 'No files match this search.' : 'No files found. Upload files or add them under the storage root.'}</td></tr>`;
    return;
  }
  $('files-body').innerHTML = files.map(file => `<tr>
    <td><div class="file-name">${esc(file.name)}</div><div class="file-sub">${esc(file.path)}</div></td>
    <td class="size-cell">${bytes(file.size)}</td><td class="date-cell">${date(file.modified)}</td>
    <td class="file-actions">
      <a class="small-action" href="/api/files/download?path=${encodeURIComponent(file.path)}">Download</a>
      <button class="small-action preview-file" data-path="${esc(file.path)}">Preview</button>
      <button class="small-action history-file" data-path="${esc(file.path)}">History</button>
      <button class="small-action move-file" data-path="${esc(file.path)}">Move / rename</button>
      <button class="small-action danger-action delete-file" data-path="${esc(file.path)}">Delete</button>
    </td>
  </tr>`).join('');
  document.querySelectorAll('.preview-file').forEach(button => button.addEventListener('click', () => {
    const url = `/api/files/preview?path=${encodeURIComponent(button.dataset.path)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
  }));
  document.querySelectorAll('.history-file').forEach(button => button.addEventListener('click', () => showVersionHistory(button.dataset.path)));
  document.querySelectorAll('.move-file').forEach(button => button.addEventListener('click', async () => {
    const source = button.dataset.path;
    const destination = prompt('New relative path (rename or move):', source);
    if (!destination || destination === source) return;
    try {
      await api('/api/files/move', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({source, destination}) });
      notify('File moved. Existing grants were updated.');
      await Promise.all([refreshFiles(), refreshFolders(), refreshGrants()]);
    } catch (e) { notify(e.message, true); }
  }));
  document.querySelectorAll('.delete-file').forEach(button => button.addEventListener('click', async () => {
    const path = button.dataset.path;
    if (!confirm(`Delete ${path}? A local recovery snapshot will be created first.`)) return;
    try {
      await api(`/api/files?path=${encodeURIComponent(path)}`, { method: 'DELETE' });
      notify('File deleted. A recovery snapshot is available in History.');
      await Promise.all([refreshFiles(), refreshGrants()]);
    } catch (e) { notify(e.message, true); }
  }));
}

let versionPath = '';
async function showVersionHistory(path = '') {
  versionPath = path;
  $('version-title').textContent = path ? `History · ${path}` : 'All recovery snapshots';
  $('create-version').disabled = !path;
  $('version-panel').classList.remove('hidden');
  $('versions-body').innerHTML = '<tr><td colspan="5" class="empty">Loading versions…</td></tr>';
  try {
    const data = await api(path ? `/api/versions?path=${encodeURIComponent(path)}` : '/api/versions');
    const versions = data.versions || [];
    $('versions-body').innerHTML = versions.length ? versions.map(version => `<tr>
      <td class="date-cell">${date(version.createdAt)}</td><td>${esc(version.reason)}</td><td>${bytes(version.size)}</td>
      <td class="hash-cell">${esc(version.sha256)}</td>
      <td><button class="small-action restore-version" data-id="${esc(version.id)}" data-path="${esc(version.path)}">Restore</button></td>
    </tr>`).join('') : '<tr><td colspan="5" class="empty">No snapshots exist for this file yet.</td></tr>';
    document.querySelectorAll('.restore-version').forEach(button => button.addEventListener('click', async () => {
      const original = button.dataset.path;
      const destination = prompt('Restore destination (must not already exist):', original);
      if (!destination) return;
      try {
        await api(`/api/versions/${encodeURIComponent(button.dataset.id)}/restore`, { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({destination}) });
        notify('Version restored and integrity verified.');
        await refreshFiles();
      } catch (e) { notify(e.message, true); }
    }));
  } catch (e) { $('versions-body').innerHTML = `<tr><td colspan="5" class="empty">${esc(e.message)}</td></tr>`; }
}


async function refreshPeers() {
  const [all, trusted] = await Promise.all([api('/api/peers'), api('/api/trusted-peers')]);
  const peers = all.peers || [];
  const inbound = trusted.peers || [];
  const outgoing = peers.filter(peer => peer.direction === 'OUTGOING');
  $('metric-peers').textContent = peers.length;
  $('share-peer').innerHTML = inbound.length
    ? '<option value="">Choose receiving device</option>' + inbound.map(peer => `<option value="${esc(peer.nodeId)}">${esc(peer.name)}</option>`).join('')
    : '<option value="">No incoming paired devices</option>';
  $('remote-peer').innerHTML = outgoing.length
    ? '<option value="">Choose source device</option>' + outgoing.map(peer => `<option value="${esc(peer.nodeId)}">${esc(peer.name)}</option>`).join('')
    : '<option value="">No outgoing peers</option>';
  if (!peers.length) {
    $('peers-list').innerHTML = '<div class="empty">No paired devices yet. Generate an invitation on one node, then enter its URL and code on the other node.</div>';
    return;
  }
  $('peers-list').innerHTML = peers.map(peer => `<div class="device-card">
    <div class="device-card-top"><div class="device-name">${esc(peer.name)}</div><span class="direction ${peer.direction === 'OUTGOING' ? 'outgoing' : ''}">${peer.direction === 'INCOMING' ? 'INCOMING TRUST' : 'OUTGOING PEER'}</span></div>
    <div class="device-id">${esc(peer.nodeId)}</div>
    ${peer.baseUrl ? `<div class="device-url">${esc(peer.baseUrl)}</div>` : '<div class="device-url">Can request files you share with it.</div>'}
    <div class="device-actions"><button class="small-action danger-action disconnect" data-id="${esc(peer.nodeId)}" data-direction="${esc(peer.direction)}">Remove pairing</button></div>
  </div>`).join('');
  document.querySelectorAll('.disconnect').forEach(button => button.addEventListener('click', async () => {
    const direction = button.dataset.direction;
    if (!confirm(`Remove ${direction.toLowerCase()} pairing? Existing grants for an incoming peer will also be removed.`)) return;
    try {
      await api(`/api/peers/${encodeURIComponent(button.dataset.id)}?direction=${direction}`, { method: 'DELETE' });
      notify('Pairing removed.');
      await refreshAll();
    } catch (e) { notify(e.message, true); }
  }));
}

async function refreshGrants() {
  const data = await api('/api/grants');
  const grants = data.grants || [];
  $('metric-shares').textContent = grants.length;
  if (!grants.length) {
    $('grants-body').innerHTML = '<tr><td colspan="5" class="empty">No active shares. Grant access to a local file above.</td></tr>';
    return;
  }
  $('grants-body').innerHTML = grants.map(grant => `<tr>
    <td><div class="file-name">${esc(grant.path)}</div></td><td>${esc(grant.peerName)}</td>
    <td>${esc(grant.permission === 'MODIFY' ? 'View · Download · Delete' : 'View · Download')}</td>
    <td class="date-cell">${date(grant.createdAt)}</td>
    <td><button class="small-action danger-action revoke" data-id="${esc(grant.id)}">Revoke</button></td>
  </tr>`).join('');
  document.querySelectorAll('.revoke').forEach(button => button.addEventListener('click', async () => {
    if (!confirm('Revoke this device’s access? The original file will remain on this device.')) return;
    try { await api(`/api/grants/${encodeURIComponent(button.dataset.id)}`, { method: 'DELETE' }); notify('Access revoked.'); await refreshGrants(); }
    catch (e) { notify(e.message, true); }
  }));
}

async function loadRemoteShares() {
  const peerId = $('remote-peer').value;
  if (!peerId) { notify('Choose a source device first.', true); return; }
  $('remote-body').innerHTML = '<tr><td colspan="4" class="empty">Contacting remote device…</td></tr>';
  try {
    const data = await api(`/api/remote-shares?peerId=${encodeURIComponent(peerId)}`);
    remoteFiles = data.shares || [];
    selectedRemotePeer = peerId;
    renderRemoteFiles();
  } catch (e) {
    $('remote-body').innerHTML = `<tr><td colspan="4" class="empty">${esc(e.message)}</td></tr>`;
    notify(e.message, true);
  }
}
function renderRemoteFiles() {
  const term = ($('remote-search').value || '').toLowerCase();
  const shares = remoteFiles.filter(share => `${share.name} ${share.path || ''}`.toLowerCase().includes(term));
  if (!shares.length) {
    $('remote-body').innerHTML = `<tr><td colspan="4" class="empty">${remoteFiles.length ? 'No remote files match this search.' : 'This device has not shared any files with you.'}</td></tr>`;
    return;
  }
  $('remote-body').innerHTML = shares.map(share => `<tr>
    <td><div class="file-name">${esc(share.name)}</div><div class="file-sub">${esc(share.path || "")}</div></td><td class="size-cell">${bytes(share.size)}</td>
    <td>${esc(share.kind === 'FOLDER' ? `${share.fileCount || 0} files · folder` : (share.permission === 'MODIFY' ? 'Can delete original' : 'Download only'))}</td>
    <td>${share.kind === 'FOLDER'
      ? `<a class="small-action" href="/api/remote-folder-download/${encodeURIComponent(selectedRemotePeer)}/${encodeURIComponent(share.shareId)}">Download ZIP</a>`
      : `<a class="small-action" href="/api/remote-download/${encodeURIComponent(selectedRemotePeer)}/${encodeURIComponent(share.shareId)}">Download</a>${share.permission === 'MODIFY' ? ` <button class="small-action danger-action remote-delete" data-peer="${esc(selectedRemotePeer)}" data-share="${esc(share.shareId)}">Delete original</button>` : ''}`}</td>
  </tr>`).join('');
  document.querySelectorAll('.remote-delete').forEach(button => button.addEventListener('click', async () => {
    if (!confirm('Delete the original file from the remote device? This cannot be undone.')) return;
    try {
      await api(`/api/remote-shares/${encodeURIComponent(button.dataset.peer)}/${encodeURIComponent(button.dataset.share)}`, { method: 'DELETE' });
      notify('Original deleted on the owner node. Its administrator may have a local recovery snapshot.');
      await loadRemoteShares();
    } catch (e) { notify(e.message, true); }
  }));
}

async function refreshActivity() {
  const data = await api('/api/activity');
  const events = data.events || [];
  $('activity-body').innerHTML = events.length ? events.map(event => `<tr>
    <td class="date-cell">${date(event.time)}</td><td>${esc(event.event)}</td>
    <td>${esc(event.actor)}</td><td>${esc(event.detail)}</td>
  </tr>`).join('') : '<tr><td colspan="4" class="empty">No recorded activity yet.</td></tr>';
}

async function refreshAll() {
  try { await refreshStatus(); await Promise.all([refreshFiles(), refreshFolders(), refreshPeers(), refreshGrants(), refreshActivity(), refreshMfa()]); }
  catch (e) { notify(e.message, true); }
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await api('/api/auth/login', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({username: $('login-username').value, password: $('login-password').value, code: $('login-code').value}) });
    $('login-form').reset();
    mfaEnabled = Boolean((await api('/api/auth/status')).mfaEnabled);
    hideAuthScreen();
    notify('Signed in.');
    await refreshAll();
  } catch (e) { notify(e.message, true); $('login-password').focus(); }
});
$('logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', {method: 'POST'}); }
  catch (e) { /* A lost session is already effectively signed out. */ }
  showAuthScreen();
  notify('Signed out.');
});
$('setup-mfa').addEventListener('click', async () => {
  try {
    const setup = await api('/api/mfa/setup', {method: 'POST'});
    $('mfa-secret').textContent = setup.secret;
    $('mfa-uri').textContent = setup.otpauthUri;
    $('mfa-setup').classList.remove('hidden');
    $('mfa-enable-code').focus();
  } catch (e) { notify(e.message, true); }
});
$('confirm-mfa').addEventListener('click', async () => {
  const code = $('mfa-enable-code').value.trim();
  try {
    const result = await api('/api/mfa/enable', {method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({code})});
    $('mfa-setup').classList.add('hidden');
    $('mfa-enable-code').value = '';
    $('recovery-codes').textContent = result.recoveryCodes.join('\n');
    $('recovery-codes-panel').classList.remove('hidden');
    notify('MFA enabled. Save the recovery codes somewhere secure.');
    await refreshMfa();
  } catch (e) { notify(e.message, true); }
});
$('disable-mfa-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await api('/api/mfa/disable', {method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({password: $('disable-mfa-password').value, code: $('disable-mfa-code').value})});
    $('disable-mfa-form').reset();
    $('recovery-codes-panel').classList.add('hidden');
    mfaEnabled = false;
    notify('MFA disabled.');
    await refreshMfa();
  } catch (e) { notify(e.message, true); }
});

$('refresh-files').addEventListener('click', async () => { try { await Promise.all([refreshFiles(), refreshFolders()]); notify('File index refreshed.'); } catch (e) { notify(e.message, true); } });
$('refresh-folders').addEventListener('click', async () => { try { await refreshFolders(); notify('Folders refreshed.'); } catch (e) { notify(e.message, true); } });
$('refresh-peers').addEventListener('click', async () => { try { await refreshPeers(); notify('Device list refreshed.'); } catch (e) { notify(e.message, true); } });
$('refresh-grants').addEventListener('click', async () => { try { await refreshGrants(); notify('Shares refreshed.'); } catch (e) { notify(e.message, true); } });
$('load-remote').addEventListener('click', loadRemoteShares);
$('file-search').addEventListener('input', renderLocalFiles);
$('remote-search').addEventListener('input', renderRemoteFiles);
$('admin-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const currentPassword = $('current-password').value;
  const newPassword = $('new-password').value;
  if (newPassword !== $('confirm-password').value) { notify('New password confirmation does not match.', true); return; }
  try {
    await api('/api/admin/password', { method: 'PUT', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({ currentPassword, newPassword }) });
    $('admin-password-form').reset();
    notify('Password changed. Sign in again with the new password.');
    await bootstrapAuth();
  } catch (e) { notify(e.message, true); }
});
$('refresh-activity').addEventListener('click', async () => { try { await refreshActivity(); notify('Activity refreshed.'); } catch (e) { notify(e.message, true); } });
$('choose-upload').addEventListener('click', () => $('upload-files').click());
$('choose-folder-upload').addEventListener('click', () => $('upload-folder').click());
async function uploadSelectedFiles(items, preserveFolders) {
  if (!items.length) return;
  let completed = 0;
  try {
    for (const file of items) {
      const relative = preserveFolders ? (file.webkitRelativePath || file.name) : file.name;
      const url = `/api/files/upload?path=${encodeURIComponent(relative)}${preserveFolders ? '&createParents=true' : ''}`;
      await api(url, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file });
      completed++;
    }
    notify(`Uploaded ${completed} file${completed === 1 ? '' : 's'}.`);
    await Promise.all([refreshFiles(), refreshFolders()]);
  } catch (e) { notify(`Uploaded ${completed}/${items.length}. ${e.message}`, true); await Promise.all([refreshFiles(), refreshFolders()]); }
}
$('upload-files').addEventListener('change', async () => {
  await uploadSelectedFiles([...$('upload-files').files], false);
  $('upload-files').value = '';
});
$('upload-folder').addEventListener('change', async () => {
  await uploadSelectedFiles([...$('upload-folder').files], true);
  $('upload-folder').value = '';
});
$('create-version').addEventListener('click', async () => {
  if (!versionPath) return;
  try {
    await api('/api/versions', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({path: versionPath}) });
    notify('Snapshot created.');
    await showVersionHistory(versionPath);
  } catch (e) { notify(e.message, true); }
});
$('close-versions').addEventListener('click', () => $('version-panel').classList.add('hidden'));
$('all-versions').addEventListener('click', () => showVersionHistory(''));
$('create-folder').addEventListener('click', async () => {
  const name = prompt('New folder name (inside the storage root):');
  if (!name) return;
  try {
    await api('/api/folders', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({path: name}) });
    notify('Folder created.');
    await Promise.all([refreshFiles(), refreshFolders()]);
  } catch (e) { notify(e.message, true); }
});

$('generate-invite').addEventListener('click', async () => {
  try {
    const invite = await api('/api/invites', { method: 'POST' });
    $('invite-result').classList.remove('hidden');
    $('invite-result').innerHTML = `<div class="invite-code">${esc(invite.code)}</div><div class="invite-expiry">Expires at ${date(invite.expiresAt)} · one use only</div>`;
    notify('Pairing code generated.');
  } catch (e) { notify(e.message, true); }
});

$('pair-device').addEventListener('click', async () => {
  const baseUrl = $('peer-url').value.trim();
  const code = $('pairing-code').value.trim().toUpperCase();
  if (!baseUrl || !code) { notify('Enter the other node URL and its one-time code.', true); return; }
  const button = $('pair-device'); button.disabled = true; button.textContent = 'Pairing…';
  try {
    const result = await api('/api/peers', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody({baseUrl, code}) });
    $('pairing-code').value = '';
    notify(`Paired with ${result.nodeName}.`);
    await refreshAll();
  } catch (e) { notify(e.message, true); }
  finally { button.disabled = false; button.textContent = 'Pair with device'; }
});

$('share-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const values = { path: $('share-path').value.trim(), peerId: $('share-peer').value, permission: $('share-permission').value };
  if (!values.peerId) { notify('Choose a receiving device. Pairing must be initiated from that device first.', true); return; }
  try {
    await api('/api/grants', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: formBody(values) });
    $('share-path').value = '';
    notify('Access granted. Original files remain on this device.');
    await refreshGrants();
  } catch (e) { notify(e.message, true); }
});

// WatchService revisions allow nodes to reflect filesystem changes made outside the dashboard.
// The browser polls only a small status payload; a full index scan runs only when the revision changes.
setInterval(async () => {
  if (statusPollBusy || !$('auth-screen').classList.contains('hidden')) return;
  statusPollBusy = true;
  try { await refreshStatus(); } catch (_) { /* transient/offline node; next poll retries */ }
  finally { statusPollBusy = false; }
}, 5000);

bootstrapAuth();
