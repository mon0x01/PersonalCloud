const $ = (id) => document.getElementById(id);
let toastTimer;

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

async function refreshStatus() {
  const status = await api('/api/status');
  $('node-name').textContent = status.nodeName;
  $('node-id-short').textContent = status.nodeId.slice(0, 8);
  $('footer-node').textContent = `Node ${status.nodeId}`;
  $('storage-root').textContent = status.storageRoot;
}

async function refreshFiles() {
  const data = await api('/api/files');
  const files = data.files || [];
  $('metric-files').textContent = files.length;
  if (!files.length) {
    $('files-body').innerHTML = '<tr><td colspan="4" class="empty">No files found. Add files under the storage root shown above, then refresh the index.</td></tr>';
    return;
  }
  $('files-body').innerHTML = files.map(file => `<tr>
    <td><div class="file-name">${esc(file.name)}</div><div class="file-sub">${esc(file.path)}</div></td>
    <td class="size-cell">${bytes(file.size)}</td><td class="date-cell">${date(file.modified)}</td>
    <td><a class="small-action" href="/api/files/download?path=${encodeURIComponent(file.path)}">Download</a></td>
  </tr>`).join('');
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
    const shares = data.shares || [];
    if (!shares.length) {
      $('remote-body').innerHTML = '<tr><td colspan="4" class="empty">This device has not shared any files with you.</td></tr>';
      return;
    }
    $('remote-body').innerHTML = shares.map(share => `<tr>
      <td><div class="file-name">${esc(share.name)}</div></td><td class="size-cell">${bytes(share.size)}</td>
      <td>${esc(share.permission === 'MODIFY' ? 'Can delete original' : 'Download only')}</td>
      <td><a class="small-action" href="/api/remote-download/${encodeURIComponent(peerId)}/${encodeURIComponent(share.shareId)}">Download</a>
      ${share.permission === 'MODIFY' ? ` <button class="small-action danger-action remote-delete" data-peer="${esc(peerId)}" data-share="${esc(share.shareId)}">Delete original</button>` : ''}</td>
    </tr>`).join('');
    document.querySelectorAll('.remote-delete').forEach(button => button.addEventListener('click', async () => {
      if (!confirm('Delete the original file from the remote device? This cannot be undone.')) return;
      try {
        await api(`/api/remote-shares/${encodeURIComponent(button.dataset.peer)}/${encodeURIComponent(button.dataset.share)}`, { method: 'DELETE' });
        notify('Original file deleted on the remote device.');
        await loadRemoteShares();
      } catch (e) { notify(e.message, true); }
    }));
  } catch (e) {
    $('remote-body').innerHTML = `<tr><td colspan="4" class="empty">${esc(e.message)}</td></tr>`;
    notify(e.message, true);
  }
}

async function refreshAll() {
  try { await refreshStatus(); await Promise.all([refreshFiles(), refreshPeers(), refreshGrants()]); }
  catch (e) { notify(e.message, true); }
}

$('refresh-files').addEventListener('click', async () => { try { await refreshFiles(); notify('File index refreshed.'); } catch (e) { notify(e.message, true); } });
$('refresh-peers').addEventListener('click', async () => { try { await refreshPeers(); notify('Device list refreshed.'); } catch (e) { notify(e.message, true); } });
$('refresh-grants').addEventListener('click', async () => { try { await refreshGrants(); notify('Shares refreshed.'); } catch (e) { notify(e.message, true); } });
$('load-remote').addEventListener('click', loadRemoteShares);

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
    notify('File access granted. The file remains on this device.');
    await refreshGrants();
  } catch (e) { notify(e.message, true); }
});

refreshAll();
