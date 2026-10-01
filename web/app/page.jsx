'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

const operations = [
  { id: 'directory.find_users', label: 'Find users', detail: 'Search basic user profiles', icon: 'users' },
  { id: 'directory.find_groups', label: 'Find groups', detail: 'Search directory groups', icon: 'layers' },
  { id: 'directory.list_group_members', label: 'Group members', detail: 'View direct membership', icon: 'network' },
];

const readOperation = {
  users: 'directory.find_users',
  groups: 'directory.find_groups',
  members: 'directory.list_group_members',
};

function Icon({ name, size = 20, strokeWidth = 1.8 }) {
  const common = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true };
  const shapes = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    link: <><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></>,
    users: <><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></>,
    layers: <><path d="m12 2 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 17l9 5 9-5"/></>,
    network: <><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M5 17v-3h14v3"/></>,
    shield: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></>,
    arrow: <><path d="M5 12h14m-6-6 6 6-6 6"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    refresh: <><path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4"/></>,
    logout: <><path d="M10 17l5-5-5-5m5 5H3"/><path d="M12 3h6a3 3 0 0 1 3 3v12a3 3 0 0 1-3 3h-6"/></>,
    trash: <><path d="M3 6h18M8 6V4h8v2m3 0-1 15H6L5 6M10 10v7m4-7v7"/></>,
    chevron: <path d="m9 18 6-6-6-6"/>,
    bolt: <path d="m13 2-9 12h7l-1 8 10-12h-7l0-8Z"/>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>,
    database: <><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></>,
  };
  return <svg {...common}>{shapes[name] || shapes.grid}</svg>;
}

async function jsonRequest(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', ...options });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Your portal session has expired. Please sign in again.');
    if (response.status === 403) throw new Error('This action is not authorised for the current session.');
    if (response.status === 409) throw new Error('This action is no longer available. Refresh and try again.');
    throw new Error(`The request could not be completed (${response.status}).`);
  }
  return response.json();
}

function shortID(value) {
  if (!value) return '—';
  return value.length > 22 ? `${value.slice(0, 12)}…${value.slice(-7)}` : value;
}

function dateLabel(value) {
  if (!value || value.startsWith('0001-')) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function Spinner() { return <span className="spinner" aria-hidden="true"/>; }

function ConnectChoices({ session, method, onMethodChange }) {
  return <div className="connect-choices">
    <div className="connect-methods" role="group" aria-label="Microsoft connection method">
      <button type="button" disabled={!session.canConnect} className={`connect-method ${method === 'reference' ? 'selected' : ''}`} onClick={() => onMethodChange('reference')} aria-pressed={method === 'reference'}><span className="operation-icon"><Icon name="link" size={20}/></span><strong>Existing connection</strong><small>PingFederate browser journey and Reference ID handoff</small><span className={`method-badge ${session.canConnect ? 'ready' : ''}`}>{session.canConnect ? 'Available' : 'Unavailable for this account'}</span></button>
      <button type="button" disabled={!session.canSamlConnect} className={`connect-method ${method === 'saml' ? 'selected' : ''}`} onClick={() => onMethodChange('saml')} aria-pressed={method === 'saml'}><span className="operation-icon"><Icon name="shield" size={20}/></span><strong>SAML token exchange</strong><small>PF assertion, Entra bearer grant and Graph OBO</small><span className={`method-badge ${session.canSamlConnect ? 'ready' : ''}`}>{session.canSamlConnect ? 'Available' : 'Unavailable for this account'}</span></button>
    </div>
    {method === 'reference' ? session.canConnect ? <form action="/connect" method="post"><input type="hidden" name="csrf" value={session.csrf}/><button className="button button-primary" disabled={session.busy || session.pending}>Connect Microsoft <Icon name="arrow" size={17}/></button></form> : <p className="helper-text">The PingFederate browser journey URL is not configured.</p> : session.canSamlConnect ? <form action="/connect/saml" method="post"><input type="hidden" name="csrf" value={session.csrf}/><button className="button button-primary" disabled={session.busy || session.pending}>Exchange and connect <Icon name="arrow" size={17}/></button></form> : <div className="callout" role="status"><Icon name="lock" size={20}/><span>This path requires a dedicated local PF exchange policy, a per-user Entra mapping and a read-only Graph OBO client.</span></div>}
  </div>;
}

export default function PortalPage() {
  const [session, setSession] = useState(null);
  const [connections, setConnections] = useState([]);
  const [selectedConnection, setSelectedConnection] = useState('');
  const [selectedOps, setSelectedOps] = useState(operations.map((op) => op.id));
  const [activeTab, setActiveTab] = useState('users');
  const [prefix, setPrefix] = useState('');
  const [groupID, setGroupID] = useState('');
  const [results, setResults] = useState(null);
  const [action, setAction] = useState('');
  const [notice, setNotice] = useState(null);
  const [loading, setLoading] = useState(true);
  const [connectionMethod, setConnectionMethod] = useState(null);
  const lastCompletedConnection = useRef('');

  const refresh = useCallback(async () => {
    const state = await jsonRequest('/api/session');
    setSession(state);
    setConnectionMethod((current) => current && (current === 'reference' ? state.canConnect : state.canSamlConnect) ? current : state.canConnect ? 'reference' : state.canSamlConnect ? 'saml' : null);
    if (!state.signedIn) {
      setConnections([]);
      setSelectedConnection('');
      setResults(null);
      lastCompletedConnection.current = '';
      return;
    }
    const items = await jsonRequest('/api/connections');
    const list = Array.isArray(items) ? items : [];
    setConnections(list);
    if (state.connectionId && state.connectionId !== lastCompletedConnection.current) {
      const completed = list.find((item) => item.connection_id === state.connectionId);
      if (completed) {
        setConnectionMethod(completed.mode === 'saml' ? 'saml' : 'reference');
        lastCompletedConnection.current = state.connectionId;
      }
    }
    setSelectedConnection((previous) => {
      if (state.delegationActive && list.some((item) => item.connection_id === state.delegationConnectionId)) return state.delegationConnectionId;
      return list.some((item) => item.connection_id === previous) ? previous : (list[0]?.connection_id || '');
    });
  }, []);

  useEffect(() => {
    let mounted = true;
    refresh().catch((error) => { if (mounted) setNotice({ type: 'error', text: error.message }); }).finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [refresh]);

  useEffect(() => {
    if (!session?.busy && !session?.pending) return;
    const timer = window.setInterval(() => refresh().catch(() => {}), 3000);
    return () => window.clearInterval(timer);
  }, [session?.busy, session?.pending, refresh]);

  const selected = useMemo(() => connections.find((item) => item.connection_id === selectedConnection), [connections, selectedConnection]);
  const allowed = (kind) => session?.delegationOps?.includes(readOperation[kind]) || false;
  const hasDelegation = Boolean(session?.delegationActive);

  async function submit(path, values, successMessage) {
    if (!session?.csrf) return;
    setAction(path);
    setNotice(null);
    try {
      const form = new URLSearchParams();
      form.set('csrf', session.csrf);
      Object.entries(values).forEach(([key, value]) => {
        if (Array.isArray(value)) value.forEach((item) => form.append(key, item));
        else form.set(key, value);
      });
      await jsonRequest(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form });
      await refresh();
      setNotice({ type: 'success', text: successMessage });
    } catch (error) {
      setNotice({ type: 'error', text: error.message });
    } finally {
      setAction('');
    }
  }

  function toggleOperation(id) {
    setSelectedOps((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  }

  async function grant() {
    if (!selectedConnection || selectedOps.length === 0) {
      setNotice({ type: 'error', text: 'Select a connection and at least one read operation.' });
      return;
    }
    await submit('/delegations', { connection_id: selectedConnection, operation: selectedOps }, 'One-hour agent delegation is active.');
  }

  async function revoke() {
    await submit('/delegations/revoke', {}, 'Agent delegation revoked.');
    setResults(null);
  }

  async function disconnect() {
    if (!selectedConnection || !window.confirm('Disconnect this Microsoft connection? Its delegations will also be revoked.')) return;
    await submit('/connections/disconnect', { connection_id: selectedConnection }, 'Microsoft connection removed.');
    setResults(null);
  }

  async function read(kind = activeTab, cursor = '', targetGroup = groupID) {
    if (!session?.csrf || !allowed(kind)) return;
    if (kind === 'members' && !targetGroup.trim()) {
      setNotice({ type: 'error', text: 'Enter or select a group ID first.' });
      return;
    }
    setAction('read');
    setNotice(null);
    try {
      const form = new URLSearchParams({ csrf: session.csrf, kind });
      if (kind === 'members') form.set('group_id', targetGroup.trim());
      else if (!cursor) form.set('prefix', prefix.trim());
      if (cursor) form.set('cursor', cursor);
      const page = await jsonRequest('/directory/read', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form });
      setActiveTab(kind);
      setResults((old) => ({ kind, items: cursor && old?.kind === kind ? [...old.items, ...(page.items || [])] : (page.items || []), nextCursor: page.next_cursor || '' }));
    } catch (error) {
      setNotice({ type: 'error', text: error.message });
    } finally {
      setAction('');
    }
  }

  const stage = !session?.signedIn ? 0 : connections.length === 0 ? 1 : hasDelegation ? 3 : 2;

  return <div className="shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-symbol"><Icon name="network" size={23}/></div><div><strong>Broker Portal</strong><small>Directory workspace</small></div></div>
      <div className="sidebar-section">WORKSPACE</div>
      <nav aria-label="Main navigation">
        <a className="nav-item active" href="#overview"><Icon name="grid" size={18}/> Overview</a>
        <a className="nav-item" href="#connections"><Icon name="link" size={18}/> Connections</a>
        <a className="nav-item" href="#delegation"><Icon name="shield" size={18}/> Delegations</a>
        <a className="nav-item" href="#explorer"><Icon name="search" size={18}/> Directory explorer</a>
      </nav>
      <div className="sidebar-bottom"><div className="environment"><span className="environment-dot"/> LOCAL ENVIRONMENT</div><div className="sidebar-caption">PingFederate · Microsoft Graph<br/>Read-only access by design</div></div>
    </aside>

    <main className="main" id="overview">
      <header className="topbar"><div className="breadcrumbs">Workspace <Icon name="chevron" size={14}/> <span>Overview</span></div><div className="topbar-right"><span className="topbar-status"><span className="status-dot"/>{session?.signedIn ? 'Signed in to PingFederate' : 'Not signed in'}</span>{session?.signedIn && <form action="/logout" method="post"><input type="hidden" name="csrf" value={session.csrf}/><button className="icon-button" title="Sign out" aria-label="Sign out"><Icon name="logout" size={18}/></button></form>}</div></header>

      {notice && <div className={`notice ${notice.type}`} role="status"><Icon name={notice.type === 'error' ? 'shield' : 'check'} size={18}/><span>{notice.text}</span><button onClick={() => setNotice(null)} aria-label="Dismiss notification">×</button></div>}

      <section className="hero"><div className="hero-glow"/><div className="hero-content"><div className="eyebrow"><span className="eyebrow-line"/> SECURE DIRECTORY BRIDGE</div><h1>One connection.<br/><em>Controlled access.</em></h1><p>Connect Microsoft through PingFederate, grant only the reads an agent needs, and explore your directory without exposing tokens to the browser.</p><div className="hero-actions">{session?.signedIn ? <a className="button button-light" href="#connections">Manage connections <Icon name="arrow" size={17}/></a> : <a className="button button-light" href="/auth/login">Sign in with PingFederate <Icon name="arrow" size={17}/></a>}<span className="hero-note"><Icon name="lock" size={15}/> Tokens stay server-side</span></div></div><div className="hero-art" aria-hidden="true"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="center-mark"><Icon name="shield" size={42} strokeWidth={1.4}/></div><div className="orbit-chip chip-one"><Icon name="layers" size={22}/></div><div className="orbit-chip chip-two"><Icon name="users" size={22}/></div><div className="orbit-chip chip-three"><Icon name="database" size={22}/></div></div></section>

      <div className="section-heading"><div><span className="overline">YOUR JOURNEY</span><h2>From connection to insight</h2></div><span className="stage-label">Step {stage} of 3 complete</span></div>
      <div className="steps">{[
        { n: 1, title: 'Authenticate', detail: 'Sign in with PingFederate', icon: 'lock' },
        { n: 2, title: 'Connect Microsoft', detail: 'Create a delegated connection', icon: 'link' },
        { n: 3, title: 'Grant & explore', detail: 'Read with explicit agent consent', icon: 'search' },
      ].map((item) => <div className={`step ${stage >= item.n ? 'complete' : stage + 1 === item.n ? 'current' : ''}`} key={item.n}><div className="step-icon"><Icon name={stage >= item.n ? 'check' : item.icon} size={20}/></div><div><span>0{item.n}</span><strong>{item.title}</strong><small>{item.detail}</small></div></div>)}</div>

      {loading ? <div className="loading-card"><Spinner/> Loading your workspace…</div> : !session?.signedIn ? <section className="empty-card"><div className="empty-icon"><Icon name="lock" size={28}/></div><h2>Your directory starts here</h2><p>Sign in to see your saved connections and manage delegated read access.</p><a className="button button-primary" href="/auth/login">Sign in with PingFederate <Icon name="arrow" size={17}/></a></section> : <>
        {(session.busy || session.pending) && <div className="flow-banner"><Spinner/><div><strong>{session.busy ? 'Connecting to Microsoft…' : 'Waiting for Microsoft sign-in'}</strong><span>The page updates when your connection finishes.</span></div>{session.pending && !session.busy && <a href="/connect/continue">Continue sign-in <Icon name="arrow" size={16}/></a>}</div>}
        {session.connectFailed && <div className="flow-banner error"><Icon name="shield" size={21}/><div><strong>Connection could not be completed</strong><span>You can start a fresh attempt below.</span></div></div>}

        <section id="connections" className="section"><div className="section-heading"><div><span className="overline">01 / CONNECTIONS</span><h2>Microsoft connections</h2><p>Owner-bound connections saved securely in the broker.</p></div><span className="count-pill">{connections.length} {connections.length === 1 ? 'connection' : 'connections'}</span></div>
          {connections.length === 0 ? <div className="empty-card compact"><div className="empty-icon"><Icon name="link" size={26}/></div><h3>No connection yet</h3><p>Connect your Microsoft account to make delegated directory reads available.</p><ConnectChoices session={session} method={connectionMethod} onMethodChange={setConnectionMethod}/></div> : <div className="connection-grid">{connections.map((connection) => <button key={connection.connection_id} type="button" className={`connection-card ${selectedConnection === connection.connection_id ? 'selected' : ''}`} onClick={() => setSelectedConnection(connection.connection_id)}><div className="connection-top"><span className="service-mark">M</span><span className={`connection-status ${connection.status === 'active' ? '' : 'warn'}`}><span className="status-dot"/>{connection.status}</span></div><strong>Microsoft Entra ID</strong><span className="connection-id" title={connection.connection_id}>{shortID(connection.connection_id)}</span><div className="connection-bottom"><span>Created {dateLabel(connection.created_at)}</span><Icon name="chevron" size={17}/></div></button>)}</div>}
          {connections.length > 0 && <div className="connection-details"><div><span className="detail-label">SELECTED CONNECTION</span><strong>{selected?.status === 'active' ? 'Ready for delegation' : 'Reconnect required'}</strong><span className="detail-text">Tenant {shortID(selected?.tenant_id)} · Object {shortID(selected?.object_id)}</span></div><button className="button button-quiet danger" onClick={disconnect} disabled={Boolean(action)}><Icon name="trash" size={16}/> Disconnect</button></div>}
          {connections.length > 0 && <div className="secondary-connect"><h3>Connect another account</h3><ConnectChoices session={session} method={connectionMethod} onMethodChange={setConnectionMethod}/></div>}
        </section>

        <section id="delegation" className="section"><div className="section-heading"><div><span className="overline">02 / DELEGATION</span><h2>Decide what the agent can read</h2><p>A separate PingFederate agent token is required for every broker read.</p></div><div className="read-only-pill"><Icon name="lock" size={14}/> READ ONLY</div></div>
          {!session.canDelegate ? <div className="callout"><Icon name="shield" size={20}/><span>Configure the dedicated portal agent client to enable live reads.</span></div> : hasDelegation ? <div className="delegation-active"><div className="active-heading"><div className="active-icon"><Icon name="check" size={21}/></div><div><strong>Agent delegation is active</strong><span>Expires {dateLabel(session.delegationExpires)}</span></div></div><div className="active-ops">{operations.filter((op) => session.delegationOps?.includes(op.id)).map((op) => <span key={op.id}><Icon name="check" size={14}/>{op.label}</span>)}</div><button className="button button-outline danger" onClick={revoke} disabled={Boolean(action)}>{action === '/delegations/revoke' ? <Spinner/> : <Icon name="trash" size={16}/>} Revoke access</button></div> : <div className="delegation-panel"><div className="operation-list">{operations.map((op) => <label className={`operation ${selectedOps.includes(op.id) ? 'chosen' : ''}`} key={op.id}><input type="checkbox" checked={selectedOps.includes(op.id)} onChange={() => toggleOperation(op.id)}/><span className="operation-icon"><Icon name={op.icon} size={20}/></span><span className="operation-copy"><strong>{op.label}</strong><small>{op.detail}</small></span><span className="operation-check"><Icon name="check" size={15}/></span></label>)}</div><div className="grant-footer"><span><Icon name="clock" size={17}/> Access expires in one hour</span><button className="button button-primary" onClick={grant} disabled={!selectedConnection || selected?.status !== 'active' || selectedOps.length === 0 || Boolean(action)}>{action === '/delegations' ? <Spinner/> : <Icon name="shield" size={17}/>} Grant agent access</button></div></div>}
        </section>

        <section id="explorer" className="section"><div className="section-heading"><div><span className="overline">03 / EXPLORER</span><h2>Explore your directory</h2><p>Results come from Microsoft Graph through the broker, using your active delegation.</p></div><div className="explorer-mark"><Icon name="bolt" size={20}/></div></div>
          <div className="explorer"><div className="tabs" role="tablist" aria-label="Directory resource">{[{ id: 'users', label: 'Users', icon: 'users' }, { id: 'groups', label: 'Groups', icon: 'layers' }, { id: 'members', label: 'Group members', icon: 'network' }].map((tab) => <button key={tab.id} type="button" role="tab" aria-selected={activeTab === tab.id} className={`tab ${activeTab === tab.id ? 'active' : ''}`} onClick={() => { setActiveTab(tab.id); setResults(null); }}><Icon name={tab.icon} size={17}/>{tab.label}</button>)}</div>
            <div className="search-row">{activeTab === 'members' ? <div className="search-field"><Icon name="layers" size={19}/><input aria-label="Group ID" placeholder="Enter a group ID (GUID)" value={groupID} onChange={(event) => setGroupID(event.target.value)} disabled={!hasDelegation}/></div> : <div className="search-field"><Icon name="search" size={19}/><input aria-label="Display-name prefix" placeholder={`Search ${activeTab} by display name…`} value={prefix} maxLength={100} onChange={(event) => setPrefix(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') read(); }} disabled={!hasDelegation}/></div>}<button className="button button-primary" onClick={() => read()} disabled={!hasDelegation || !allowed(activeTab) || Boolean(action)}>{action === 'read' ? <Spinner/> : <Icon name="search" size={17}/>} Search</button></div>
            {!hasDelegation ? <div className="results-empty"><div className="results-empty-icon"><Icon name="lock" size={27}/></div><strong>Grant access to start exploring</strong><span>Choose the read operations above, then run a directory search.</span></div> : !allowed(activeTab) ? <div className="results-empty"><div className="results-empty-icon"><Icon name="shield" size={27}/></div><strong>This operation was not delegated</strong><span>Revoke and create a new delegation with this operation selected.</span></div> : !results || results.kind !== activeTab ? <div className="results-empty"><div className="results-empty-icon"><Icon name="search" size={27}/></div><strong>Ready when you are</strong><span>Run a search to see the first page of read-only directory results.</span></div> : <div className="results"><div className="results-bar"><span>{results.items.length} {results.items.length === 1 ? 'result' : 'results'} shown</span><span>Microsoft Graph · read only</span></div>{results.items.length === 0 ? <div className="no-results">No matches on this page. Try another search.</div> : <div className="results-list">{results.items.map((item, index) => <div className="result-row" key={`${item.id}-${index}`}><div className="result-avatar">{(item.displayName || item.id || '?').slice(0, 1).toUpperCase()}</div><div className="result-copy"><strong>{item.displayName || 'Unnamed directory object'}</strong><span>{item.mail || item.userPrincipalName || item.id}</span></div>{activeTab === 'groups' && allowed('members') && <button className="button button-quiet" onClick={() => { setGroupID(item.id); read('members', '', item.id); }}>View members <Icon name="arrow" size={15}/></button>}</div>)}</div>}{results.nextCursor && <button className="load-more" onClick={() => read(activeTab, results.nextCursor)} disabled={Boolean(action)}>{action === 'read' ? <Spinner/> : <Icon name="refresh" size={16}/>} Load next page</button>}</div>}
          </div>
        </section>
      </>}
      <footer className="footer"><span>Broker Portal · Local development workspace</span><span><Icon name="shield" size={14}/> Tokens never leave the backend</span></footer>
    </main>
  </div>;
}
