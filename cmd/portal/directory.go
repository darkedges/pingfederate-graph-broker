package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var readOperations = map[string]bool{
	"directory.find_users":         true,
	"directory.find_groups":        true,
	"directory.list_group_members": true,
}

type connectionInfo struct {
	ID        string    `json:"connection_id"`
	Mode      string    `json:"mode"`
	Status    string    `json:"status"`
	TenantID  string    `json:"tenant_id"`
	ObjectID  string    `json:"object_id"`
	Scopes    string    `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
}

type directoryItem struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
	Type              string `json:"@odata.type"`
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func actionDone(w http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return
	}
	http.Redirect(w, r, "/connections", http.StatusSeeOther)
}

var connectionsHTML = template.Must(template.New("connections").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Microsoft connections</title>
<style>body{font:16px system-ui;max-width:44rem;margin:3rem auto;padding:0 1rem}button,input{font:inherit;padding:.4rem}section{border:1px solid #ccc;padding:1rem;margin:1rem 0}.note{color:#555}</style>
<h1>Microsoft connections</h1><p><a href="/">Portal home</a></p>
{{if .Items}}{{range .Items}}
<section><p>Connection <code>{{.ID}}</code> — {{.Status}}</p>
{{if and $.CanDelegate (eq .Status "active")}}
<form method="post" action="/delegations"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="connection_id" value="{{.ID}}">
<p>Grant the configured agent one hour of selected read access:</p>
<label><input type="checkbox" name="operation" value="directory.find_users" checked> Find users</label><br>
<label><input type="checkbox" name="operation" value="directory.find_groups" checked> Find groups</label><br>
<label><input type="checkbox" name="operation" value="directory.list_group_members" checked> List direct group members</label><br>
<button>Grant one-hour delegation</button></form>
{{end}}
<form method="post" action="/connections/disconnect"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="connection_id" value="{{.ID}}"><button>Disconnect this Microsoft connection</button></form></section>
{{end}}{{else}}<p>No saved Microsoft connections for this signed-in user.</p>{{end}}
{{if .DelegationActive}}
<section><h2>Agent delegation active</h2><p>Expires {{.DelegationExpires}}. Only the selected operations are authorised.</p>
{{if or .CanReadUsers .CanReadGroups}}<form method="post" action="/directory/read"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Directory search <select name="kind">{{if .CanReadUsers}}<option value="users">Users</option>{{end}}{{if .CanReadGroups}}<option value="groups">Groups</option>{{end}}</select></label> <label>Display-name prefix <input name="prefix" maxlength="100"></label> <button>Read directory</button></form>{{end}}
{{if .CanReadMembers}}<form method="post" action="/directory/read"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="kind" value="members"><label>Group ID <input name="group_id" required maxlength="36"></label> <button>Read direct members</button></form>{{end}}
<form method="post" action="/delegations/revoke"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Revoke this delegation</button></form></section>
{{else if not .CanDelegate}}<p class="note">Set PORTAL_AGENT_CLIENT_ID and PORTAL_AGENT_CLIENT_SECRET to enable live agent reads.</p>{{end}}
<p class="note">Agent tokens stay on this server. Signing out does not revoke a delegation; revoke it here or disconnect the connection.</p>
</html>`))

var directoryHTML = template.Must(template.New("directory").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Directory results</title>
<style>body{font:16px system-ui;max-width:44rem;margin:3rem auto;padding:0 1rem}li{margin:.75rem 0}.note{color:#555}</style>
<h1>Directory results</h1><p><a href="/connections">Back to connections</a></p>
{{if .Items}}<ul>{{range .Items}}<li><strong>{{.DisplayName}}</strong> <code>{{.ID}}</code>{{if .Mail}} — {{.Mail}}{{end}}{{if .UserPrincipalName}} ({{.UserPrincipalName}}){{end}}</li>{{end}}</ul>{{else}}<p>No matching entries on this page.</p>{{end}}
{{if .HasMore}}<p class="note">More results are available; this local page displays the first page only.</p>{{end}}
</html>`))

func safeOpaqueID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func (p *portal) ownerForm(w http.ResponseWriter, r *http.Request) (string, *session, bool) {
	id, s := p.current(r)
	if s == nil {
		http.Error(w, "Sign in first", http.StatusUnauthorized)
		return "", nil, false
	}
	if v := r.Header.Get("Origin"); v != "" && v != origin(p.c.publicURL) {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return "", nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !same(r.PostForm.Get("csrf"), s.csrf) {
		http.Error(w, "Invalid form", http.StatusForbidden)
		return "", nil, false
	}
	return id, s, true
}

func (p *portal) api(ctx context.Context, token, method, path string, query url.Values, body any, want int, dst any) error {
	u := *p.c.brokerURL
	u.Path = path
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.New("broker transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		p.log.Debug("portal_broker_call", "outcome", "http_error", "status", resp.StatusCode)
		return errors.New("broker rejected request")
	}
	if dst != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(dst); err != nil {
			return errors.New("invalid broker response")
		}
	}
	return nil
}

func (p *portal) loadConnections(ctx context.Context, token string) ([]connectionInfo, error) {
	var out struct {
		Items []connectionInfo `json:"items"`
	}
	if err := p.api(ctx, token, http.MethodGet, "/v1/connections", nil, nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	for _, item := range out.Items {
		if !safeOpaqueID(item.ID) {
			return nil, errors.New("invalid connection ID from broker")
		}
	}
	return out.Items, nil
}

func (p *portal) connections(w http.ResponseWriter, r *http.Request) {
	_, s := p.current(r)
	if s == nil {
		http.Error(w, "Sign in first", http.StatusUnauthorized)
		return
	}
	items, err := p.loadConnections(r.Context(), s.token)
	if err != nil {
		http.Error(w, "Could not load connections", http.StatusBadGateway)
		return
	}
	d := struct {
		Items             []connectionInfo
		CSRF              string
		CanDelegate       bool
		DelegationActive  bool
		DelegationExpires string
		CanReadUsers      bool
		CanReadGroups     bool
		CanReadMembers    bool
	}{items, s.csrf, p.c.agentClientID != "" && p.c.agentClientSecret != "", s.delegationID != "", s.delegationExpires.Format(time.RFC3339), containsOperation(s.delegationOps, "directory.find_users"), containsOperation(s.delegationOps, "directory.find_groups"), containsOperation(s.delegationOps, "directory.list_group_members")}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = connectionsHTML.Execute(w, d)
}

func (p *portal) grantDelegation(w http.ResponseWriter, r *http.Request) {
	id, s, ok := p.ownerForm(w, r)
	if !ok {
		return
	}
	if p.c.agentClientID == "" || p.c.agentClientSecret == "" {
		http.Error(w, "Agent is not configured", http.StatusServiceUnavailable)
		return
	}
	connectionID := r.PostForm.Get("connection_id")
	if !safeOpaqueID(connectionID) || len(r.PostForm["connection_id"]) != 1 || s.delegationID != "" {
		http.Error(w, "Invalid delegation request", http.StatusBadRequest)
		return
	}
	operations := r.PostForm["operation"]
	if len(operations) < 1 || len(operations) > 3 {
		http.Error(w, "Select one to three read operations", http.StatusBadRequest)
		return
	}
	seen := map[string]bool{}
	for _, operation := range operations {
		if !readOperations[operation] || seen[operation] {
			http.Error(w, "Invalid read operation", http.StatusBadRequest)
			return
		}
		seen[operation] = true
	}
	p.mu.Lock()
	live := p.sessions[id]
	if live == nil || live.delegationBusy || live.delegationID != "" {
		p.mu.Unlock()
		http.Error(w, "Delegation already in progress", http.StatusConflict)
		return
	}
	live.delegationBusy = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if live := p.sessions[id]; live != nil {
			live.delegationBusy = false
		}
		p.mu.Unlock()
	}()
	var out struct {
		ID        string    `json:"delegation_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	request := map[string]any{"agent_client_id": p.c.agentClientID, "operations": operations, "expires_in_seconds": 3600}
	if err := p.api(r.Context(), s.token, http.MethodPost, "/v1/connections/"+connectionID+"/delegations", nil, request, http.StatusCreated, &out); err != nil || !safeOpaqueID(out.ID) || !time.Now().Before(out.ExpiresAt) {
		http.Error(w, "Could not grant delegation", http.StatusBadGateway)
		return
	}
	p.mu.Lock()
	stored := false
	if live := p.sessions[id]; live != nil && same(live.token, s.token) {
		live.delegationID = out.ID
		live.delegationConnectionID = connectionID
		live.delegationExpires = out.ExpiresAt
		live.delegationOps = append([]string(nil), operations...)
		stored = true
	}
	p.mu.Unlock()
	if !stored {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = p.api(ctx, s.token, http.MethodDelete, "/v1/delegations/"+out.ID, nil, nil, http.StatusNoContent, nil)
		http.Error(w, "Sign-in session ended; delegation was revoked", http.StatusConflict)
		return
	}
	actionDone(w, r)
}

func (p *portal) revokeDelegation(w http.ResponseWriter, r *http.Request) {
	id, s, ok := p.ownerForm(w, r)
	if !ok {
		return
	}
	if !safeOpaqueID(s.delegationID) {
		http.Error(w, "No active delegation", http.StatusConflict)
		return
	}
	if err := p.api(r.Context(), s.token, http.MethodDelete, "/v1/delegations/"+s.delegationID, nil, nil, http.StatusNoContent, nil); err != nil {
		http.Error(w, "Could not revoke delegation", http.StatusBadGateway)
		return
	}
	p.mu.Lock()
	if live := p.sessions[id]; live != nil && live.delegationID == s.delegationID {
		live.delegationID = ""
		live.delegationConnectionID = ""
		live.delegationExpires = time.Time{}
		live.delegationOps = nil
	}
	p.mu.Unlock()
	actionDone(w, r)
}

func (p *portal) disconnect(w http.ResponseWriter, r *http.Request) {
	id, s, ok := p.ownerForm(w, r)
	if !ok {
		return
	}
	connectionID := r.PostForm.Get("connection_id")
	if !safeOpaqueID(connectionID) || len(r.PostForm["connection_id"]) != 1 {
		http.Error(w, "Invalid connection", http.StatusBadRequest)
		return
	}
	if err := p.api(r.Context(), s.token, http.MethodDelete, "/v1/connections/"+connectionID, nil, nil, http.StatusNoContent, nil); err != nil {
		http.Error(w, "Could not disconnect", http.StatusBadGateway)
		return
	}
	p.mu.Lock()
	if live := p.sessions[id]; live != nil {
		if live.connectionID == connectionID {
			live.connectionID = ""
		}
		if live.delegationConnectionID == connectionID {
			live.delegationID = ""
			live.delegationConnectionID = ""
			live.delegationExpires = time.Time{}
			live.delegationOps = nil
		}
	}
	p.mu.Unlock()
	actionDone(w, r)
}

func (p *portal) agentToken(ctx context.Context) (string, error) {
	u := *p.c.pfURL
	u.Path = "/as/token.oauth2"
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"broker.directory.read"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.c.agentClientID, p.c.agentClientSecret)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", errors.New("agent token transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.log.Debug("portal_agent_token", "outcome", "http_error", "status", resp.StatusCode)
		return "", errors.New("agent token rejected")
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&out); err != nil || out.AccessToken == "" || !strings.EqualFold(out.TokenType, "Bearer") || out.ExpiresIn < 1 {
		return "", errors.New("invalid agent token response")
	}
	return out.AccessToken, nil
}

func (p *portal) readDirectory(w http.ResponseWriter, r *http.Request) {
	_, s, ok := p.ownerForm(w, r)
	if !ok {
		return
	}
	if !safeOpaqueID(s.delegationID) || !time.Now().Before(s.delegationExpires) || p.c.agentClientID == "" {
		http.Error(w, "Grant agent access first", http.StatusConflict)
		return
	}
	kind := r.PostForm.Get("kind")
	prefix := r.PostForm.Get("prefix")
	cursor := r.PostForm.Get("cursor")
	if len(r.PostForm["kind"]) != 1 || len(r.PostForm["prefix"]) > 1 || len(prefix) > 100 || len(r.PostForm["cursor"]) > 1 || len(cursor) > 8192 || (cursor != "" && prefix != "") {
		http.Error(w, "Invalid directory search", http.StatusBadRequest)
		return
	}
	var path string
	var query url.Values
	switch kind {
	case "users":
		if !containsOperation(s.delegationOps, "directory.find_users") {
			http.Error(w, "Operation not delegated", http.StatusForbidden)
			return
		}
		path = "/users"
		query = url.Values{"prefix": {prefix}}
	case "groups":
		if !containsOperation(s.delegationOps, "directory.find_groups") {
			http.Error(w, "Operation not delegated", http.StatusForbidden)
			return
		}
		path = "/groups"
		query = url.Values{"prefix": {prefix}}
	case "members":
		groupID := r.PostForm.Get("group_id")
		if !containsOperation(s.delegationOps, "directory.list_group_members") {
			http.Error(w, "Operation not delegated", http.StatusForbidden)
			return
		}
		if len(r.PostForm["group_id"]) != 1 || !safeGroupID(groupID) || prefix != "" {
			http.Error(w, "Invalid group ID", http.StatusBadRequest)
			return
		}
		path = "/groups/" + groupID + "/members"
	default:
		http.Error(w, "Invalid directory search", http.StatusBadRequest)
		return
	}
	if cursor != "" {
		query = url.Values{"cursor": {cursor}}
	}
	token, err := p.agentToken(r.Context())
	if err != nil {
		http.Error(w, "Could not authenticate agent", http.StatusBadGateway)
		return
	}
	var out struct {
		Items      []directoryItem `json:"items"`
		NextCursor string          `json:"next_cursor"`
	}
	if err := p.api(r.Context(), token, http.MethodGet, "/v1/delegations/"+s.delegationID+path, query, nil, http.StatusOK, &out); err != nil {
		http.Error(w, "Directory read failed", http.StatusBadGateway)
		return
	}
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = directoryHTML.Execute(w, struct {
		Items   []directoryItem
		HasMore bool
	}{out.Items, out.NextCursor != ""})
}

func containsOperation(operations []string, want string) bool {
	for _, operation := range operations {
		if operation == want {
			return true
		}
	}
	return false
}

func safeGroupID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			continue
		}
		return false
	}
	return true
}
