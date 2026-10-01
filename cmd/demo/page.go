package main

const pageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Directory broker · local demo</title>
  <style>
    :root { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; color: #e8edf7; background: #0a1020; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 85% 0%, #21345b 0, transparent 42%), #0a1020; }
    main { max-width: 1040px; margin: auto; padding: 52px 24px 80px; }
    .eyebrow { color: #7ac7c4; text-transform: uppercase; letter-spacing: .18em; font-size: 12px; font-weight: 800; }
    h1 { font-size: clamp(32px, 5vw, 52px); margin: 10px 0 12px; letter-spacing: -.04em; }
    h2 { font-size: 20px; margin: 0 0 8px; }
    p { color: #aab8d0; line-height: 1.55; margin: 0 0 18px; }
    .intro { max-width: 750px; font-size: 17px; }
    .notice { border: 1px solid #4d726e; background: #15332f; color: #d0f3eb; border-radius: 12px; padding: 13px 16px; margin: 26px 0; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
    .card { background: #111c31; border: 1px solid #2c3b56; border-radius: 16px; padding: 22px; box-shadow: 0 16px 40px #03091633; }
    .wide { grid-column: 1 / -1; }
    .step { display: inline-grid; place-items: center; width: 30px; height: 30px; border-radius: 50%; background: #274f69; color: #b2eaf0; font-weight: 800; margin-bottom: 14px; }
    button, input, select { font: inherit; }
    button { background: #60d8ba; color: #08241e; border: 0; border-radius: 9px; padding: 10px 16px; font-weight: 800; cursor: pointer; }
    button:hover:not(:disabled) { background: #8ee9d0; }
    button:disabled { opacity: .4; cursor: not-allowed; }
    button.secondary { background: #293b57; color: #e9f0fc; }
    button.danger { background: #432e3b; color: #ffcfdd; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    .status { color: #7ce1c6; font-weight: 700; }
    .muted { color: #aab8d0; }
    .field { display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0; }
    input, select { border-radius: 9px; border: 1px solid #425474; background: #0a1427; color: #f2f6ff; padding: 10px 12px; }
    input { flex: 1; min-width: 170px; }
    .results { display: grid; gap: 8px; margin-top: 18px; }
    .result { border: 1px solid #31425c; border-radius: 10px; padding: 12px 14px; background: #0c172b; }
    .result strong { display: block; }
    .result small { color: #aab8d0; overflow-wrap: anywhere; }
    #message { min-height: 24px; margin: 24px 0 0; }
    #events { white-space: pre-wrap; color: #9facc4; background: #081121; border-radius: 10px; padding: 15px; min-height: 88px; line-height: 1.7; font-size: 13px; }
    code { overflow-wrap: anywhere; color: #b2eaf0; }
    @media(max-width: 680px) { main { padding-top: 30px; } .grid { grid-template-columns: 1fr; } .wide { grid-column: auto; } }
  </style>
</head>
<body><main>
  <div class="eyebrow">PingFederate → Microsoft Graph</div>
  <h1>Directory broker demo</h1>
  <p class="intro">Walk through a user connection, an agent delegation, read-only directory queries, and revocation. Each button calls the broker’s real HTTP handlers through a small portal backend.</p>
  <div class="notice">Local simulation: the portal, PingFederate, Entra, and Graph data on this page are simulated. No tenant, credentials, or live Microsoft data are used.</div>
  <div class="grid">
    <section class="card"><div class="step">1</div><h2>Connect a user</h2><p>The portal starts a one-use link intent, simulates the PF reference pickup, and the broker validates an Entra refresh grant.</p><div class="actions"><button id="connect">Connect Microsoft</button><span class="status" id="connection-status">Not connected</span></div></section>
    <section class="card"><div class="step">2</div><h2>Delegate to an agent</h2><p>The connected user grants one demo agent all three directory read operations for one hour.</p><div class="actions"><button id="delegate">Grant delegation</button><span class="status" id="delegation-status">No delegation</span></div></section>
    <section class="card wide"><div class="step">3</div><h2>Read directory data</h2><p>The agent presents its own PF token and the delegation ID. Try a display-name prefix or browse the sample group’s direct members.</p>
      <div class="field"><select id="kind" aria-label="Directory type"><option value="users">Users</option><option value="groups">Groups</option><option value="members">Engineering group members</option></select><input id="prefix" maxlength="100" placeholder="Optional display-name prefix" aria-label="Display-name prefix"><button id="search">Search</button></div>
      <div class="results" id="results"></div><div class="actions" style="margin-top:14px"><button class="secondary" id="next" hidden>Next page</button></div>
    </section>
    <section class="card wide"><div class="step">4</div><h2>Revoke or disconnect</h2><p>Revoking removes the agent’s permission. Disconnecting removes the saved connection and every delegation attached to it.</p><div class="actions"><button class="secondary" id="revoke">Revoke delegation</button><button class="danger" id="disconnect">Disconnect user</button></div></section>
    <section class="card wide"><h2>Flow log</h2><p>Only operation outcomes appear here. Tokens and pickup references stay on the server.</p><div id="events" role="log" aria-live="polite">Ready.</div></section>
  </div>
  <p id="message" role="status"></p>
</main>
<script>
  const el = id => document.getElementById(id);
  let state = { connections: [], delegation_active: false };
  let cursor = '';
  let currentKind = '';
  function log(line) {
    const node = el('events');
    node.textContent = (node.textContent === 'Ready.' ? '' : node.textContent + '\n') + new Date().toLocaleTimeString() + '  ' + line;
  }
  async function request(path, method) {
    const response = await fetch(path, { method: method || 'GET', headers: method ? { 'Content-Type': 'application/json' } : {} });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || 'Request failed (' + response.status + ')');
    return value;
  }
  async function refresh() {
    state = await request('/demo/state');
    const connected = state.connections.length > 0;
    el('connection-status').textContent = connected ? 'Connected' : 'Not connected';
    el('delegation-status').textContent = state.delegation_active ? 'Active for 1 hour' : 'No delegation';
    el('connect').disabled = connected;
    el('delegate').disabled = !connected || state.delegation_active;
    el('search').disabled = !state.delegation_active;
    el('revoke').disabled = !state.delegation_active;
    el('disconnect').disabled = !connected;
    if (!state.delegation_active) { cursor = ''; el('next').hidden = true; }
  }
  async function action(path, success) {
    try {
      el('message').textContent = '';
      await request(path, 'POST');
      log(success);
      await refresh();
    } catch (e) { el('message').textContent = e.message; log('Request failed: ' + e.message); }
  }
  el('connect').onclick = () => action('/demo/connect', 'Connection created after PF pickup and Entra token validation.');
  el('delegate').onclick = () => action('/demo/delegate', 'One-hour agent delegation created.');
  el('revoke').onclick = () => action('/demo/revoke', 'Agent delegation revoked.');
  el('disconnect').onclick = () => action('/demo/disconnect', 'Connection and attached delegations removed.');
  el('kind').onchange = () => { el('prefix').disabled = el('kind').value === 'members'; el('prefix').value = ''; cursor = ''; el('next').hidden = true; el('results').replaceChildren(); };
  async function read(next) {
    try {
      el('message').textContent = '';
      const kind = el('kind').value;
      if (!next) { cursor = ''; currentKind = kind; el('results').replaceChildren(); }
      const query = new URLSearchParams({ kind: kind });
      if (next) query.set('cursor', cursor);
      else if (kind !== 'members') query.set('prefix', el('prefix').value);
      const data = await request('/demo/read?' + query.toString());
      for (const item of data.items || []) {
        const card = document.createElement('div'); card.className = 'result';
        const name = document.createElement('strong'); name.textContent = item.displayName || 'Unnamed object';
        const detail = document.createElement('small'); detail.textContent = [item.mail, item.userPrincipalName, item['@odata.type'], item.id].filter(Boolean).join(' · ');
        card.append(name, detail); el('results').append(card);
      }
      if (!(data.items || []).length && !next) el('results').textContent = 'No matching objects.';
      cursor = data.next_cursor || '';
      el('next').hidden = !cursor;
      log('Agent read ' + kind + (next ? ' (next page).' : '.'));
    } catch (e) { el('message').textContent = e.message; log('Read failed: ' + e.message); }
  }
  el('search').onclick = () => read(false);
  el('next').onclick = () => { if (currentKind === el('kind').value) read(true); };
  refresh().catch(e => { el('message').textContent = e.message; });
</script></body></html>`
