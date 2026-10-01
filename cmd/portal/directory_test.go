package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLiveDirectoryDelegationFlow(t *testing.T) {
	var tokenCalls, grantCalls, readCalls, revokeCalls, disconnectCalls atomic.Int32
	pf := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if r.URL.Path != "/as/token.oauth2" || r.Method != http.MethodPost || !ok || user != "directory-agent" || password != "agent-secret" || r.FormValue("grant_type") != "client_credentials" || r.FormValue("scope") != "broker.directory.read" {
			t.Error("incorrect PF agent token request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tokenCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"agent-only-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer pf.Close()
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/connections":
			if r.Header.Get("Authorization") != "Bearer user-only-token" {
				t.Error("connection list did not use owner token")
			}
			_, _ = io.WriteString(w, `{"items":[{"connection_id":"connection-1","mode":"saml","status":"active"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connections/connection-1/delegations":
			if r.Header.Get("Authorization") != "Bearer user-only-token" {
				t.Error("grant did not use owner token")
			}
			var body struct {
				AgentClientID string   `json:"agent_client_id"`
				Operations    []string `json:"operations"`
				ExpiresIn     int64    `json:"expires_in_seconds"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.AgentClientID != "directory-agent" || body.ExpiresIn != 3600 || len(body.Operations) < 1 || body.Operations[0] != "directory.find_users" {
				t.Error("grant did not preserve selected read operation")
			}
			grantCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"delegation_id": "delegation-1", "expires_at": time.Now().Add(time.Hour)})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/delegations/delegation-1/users":
			if r.Header.Get("Authorization") != "Bearer agent-only-token" {
				t.Error("directory read did not use agent token and selected prefix")
			}
			readCalls.Add(1)
			if r.URL.Query().Get("cursor") == "cursor-1" && r.URL.Query().Get("prefix") == "" {
				_, _ = io.WriteString(w, `{"items":[{"id":"user-3","displayName":"Alice Second"}]}`)
			} else if r.URL.Query().Get("prefix") == "Ali" {
				_, _ = io.WriteString(w, `{"items":[{"id":"user-1","displayName":"Alice Example","mail":"alice@example.test"}],"next_cursor":"cursor-1"}`)
			} else {
				t.Error("directory read used unexpected search parameters")
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/delegations/delegation-1/groups":
			if r.Header.Get("Authorization") != "Bearer agent-only-token" {
				t.Error("group read did not use agent token")
			}
			readCalls.Add(1)
			_, _ = io.WriteString(w, `{"items":[{"id":"11111111-1111-1111-1111-111111111111","displayName":"Example Group"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/delegations/delegation-1/groups/11111111-1111-1111-1111-111111111111/members":
			if r.Header.Get("Authorization") != "Bearer agent-only-token" {
				t.Error("member read did not use agent token")
			}
			readCalls.Add(1)
			_, _ = io.WriteString(w, `{"items":[{"id":"user-2","displayName":"Member Example"}]}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/delegations/delegation-1":
			if r.Header.Get("Authorization") != "Bearer user-only-token" {
				t.Error("revoke did not use owner token")
			}
			revokeCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/connections/connection-1":
			if r.Header.Get("Authorization") != "Bearer user-only-token" {
				t.Error("disconnect did not use owner token")
			}
			disconnectCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected broker operation %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer broker.Close()
	publicURL, _ := url.Parse("https://localhost:8788")
	pfURL, _ := url.Parse(pf.URL)
	brokerURL, _ := url.Parse(broker.URL)
	p := newPortal(config{publicURL: publicURL, pfURL: pfURL, brokerURL: brokerURL, agentClientID: "directory-agent", agentClientSecret: "agent-secret"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.client = pf.Client()
	p.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p.sessions["session-1"] = &session{token: "user-only-token", csrf: "csrf-1", expires: time.Now().Add(time.Hour), connectionID: "connection-1"}
	server := httptest.NewTLSServer(p.handler())
	defer server.Close()
	browser := server.Client()
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	call := func(method, path string, form url.Values, requestOrigin string, accept ...string) *http.Response {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequest(method, server.URL+path, body)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-1"})
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", requestOrigin)
		}
		if len(accept) > 0 {
			req.Header.Set("Accept", accept[0])
		}
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	page := call(http.MethodGet, "/connections", nil, "")
	content, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(content), "connection-1") || !strings.Contains(string(content), "Grant one-hour delegation") {
		t.Fatal("connection controls missing")
	}
	apiList := call(http.MethodGet, "/api/connections", nil, "")
	apiContent, _ := io.ReadAll(apiList.Body)
	apiList.Body.Close()
	if apiList.StatusCode != http.StatusOK || !strings.Contains(string(apiContent), `"mode":"saml"`) {
		t.Fatal("connection method was not forwarded to the portal UI")
	}
	bad := call(http.MethodPost, "/delegations", url.Values{"csrf": {"csrf-1"}, "connection_id": {"connection-1"}, "operation": {"directory.find_users"}}, "https://evil.example")
	bad.Body.Close()
	if bad.StatusCode != http.StatusForbidden || grantCalls.Load() != 0 {
		t.Fatal("cross-origin grant accepted")
	}
	bad = call(http.MethodPost, "/delegations", url.Values{"csrf": {"csrf-1"}, "connection_id": {"connection-1"}, "operation": {"directory.delete_user"}}, "https://localhost:8788")
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest || grantCalls.Load() != 0 {
		t.Fatal("write operation accepted")
	}
	grant := call(http.MethodPost, "/delegations", url.Values{"csrf": {"csrf-1"}, "connection_id": {"connection-1"}, "operation": {"directory.find_users"}}, "https://localhost:8788", "application/json")
	grant.Body.Close()
	if grant.StatusCode != http.StatusOK || grantCalls.Load() != 1 {
		t.Fatal("delegation grant failed")
	}
	read := call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"users"}, "prefix": {"Ali"}}, "https://localhost:8788", "application/json")
	result, _ := io.ReadAll(read.Body)
	read.Body.Close()
	if read.StatusCode != http.StatusOK || !strings.Contains(string(result), "Alice Example") || strings.Contains(string(result), "agent-only-token") || strings.Contains(string(result), "user-only-token") || tokenCalls.Load() != 1 || readCalls.Load() != 1 {
		t.Fatal("directory result missing or a token leaked")
	}
	read = call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"users"}, "cursor": {"cursor-1"}}, "https://localhost:8788", "application/json")
	result, _ = io.ReadAll(read.Body)
	read.Body.Close()
	if read.StatusCode != http.StatusOK || !strings.Contains(string(result), "Alice Second") || readCalls.Load() != 2 {
		t.Fatal("directory continuation failed")
	}
	bad = call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"groups"}}, "https://localhost:8788")
	bad.Body.Close()
	if bad.StatusCode != http.StatusForbidden || tokenCalls.Load() != 2 {
		t.Fatal("non-delegated group read reached PF")
	}
	revoke := call(http.MethodPost, "/delegations/revoke", url.Values{"csrf": {"csrf-1"}}, "https://localhost:8788")
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusSeeOther || revokeCalls.Load() != 1 {
		t.Fatal("delegation revoke failed")
	}
	read = call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"users"}}, "https://localhost:8788")
	read.Body.Close()
	if read.StatusCode != http.StatusConflict || readCalls.Load() != 2 {
		t.Fatal("read after revocation accepted")
	}
	grant = call(http.MethodPost, "/delegations", url.Values{"csrf": {"csrf-1"}, "connection_id": {"connection-1"}, "operation": {"directory.find_users", "directory.find_groups", "directory.list_group_members"}}, "https://localhost:8788")
	grant.Body.Close()
	if grant.StatusCode != http.StatusSeeOther || grantCalls.Load() != 2 {
		t.Fatal("second delegation grant failed")
	}
	groupRead := call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"groups"}}, "https://localhost:8788")
	groupResult, _ := io.ReadAll(groupRead.Body)
	groupRead.Body.Close()
	if groupRead.StatusCode != http.StatusOK || !strings.Contains(string(groupResult), "Example Group") {
		t.Fatal("group read failed")
	}
	memberRead := call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"members"}, "group_id": {"11111111-1111-1111-1111-111111111111"}}, "https://localhost:8788")
	memberResult, _ := io.ReadAll(memberRead.Body)
	memberRead.Body.Close()
	if memberRead.StatusCode != http.StatusOK || !strings.Contains(string(memberResult), "Member Example") {
		t.Fatal("group-member read failed")
	}
	bad = call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"members"}, "group_id": {"not-a-group-id"}}, "https://localhost:8788")
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest || readCalls.Load() != 4 {
		t.Fatal("invalid group ID reached broker")
	}
	disconnect := call(http.MethodPost, "/connections/disconnect", url.Values{"csrf": {"csrf-1"}, "connection_id": {"connection-1"}}, "https://localhost:8788")
	disconnect.Body.Close()
	if disconnect.StatusCode != http.StatusSeeOther || disconnectCalls.Load() != 1 {
		t.Fatal("disconnect failed")
	}
	read = call(http.MethodPost, "/directory/read", url.Values{"csrf": {"csrf-1"}, "kind": {"users"}}, "https://localhost:8788")
	read.Body.Close()
	if read.StatusCode != http.StatusConflict || readCalls.Load() != 4 {
		t.Fatal("read after disconnect accepted")
	}
}

func TestConcurrentDelegationGrantCreatesOne(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var grants atomic.Int32
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if grants.Add(1) == 1 {
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"delegation_id": "delegation-1", "expires_at": time.Now().Add(time.Hour)})
	}))
	defer broker.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	publicURL, _ := url.Parse("https://localhost:8788")
	brokerURL, _ := url.Parse(broker.URL)
	p := newPortal(config{publicURL: publicURL, brokerURL: brokerURL, agentClientID: "directory-agent", agentClientSecret: "agent-secret"}, nil)
	p.sessions["session-1"] = &session{token: "user-token", csrf: "csrf-1", expires: time.Now().Add(time.Hour)}
	server := httptest.NewTLSServer(p.handler())
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	post := func() int {
		form := url.Values{"csrf": {"csrf-1"}, "connection_id": {"connection-1"}, "operation": {"directory.find_users"}}
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/delegations", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://localhost:8788")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-1"})
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	first := make(chan int, 1)
	go func() { first <- post() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first grant did not reach broker")
	}
	if status := post(); status != http.StatusConflict || grants.Load() != 1 {
		t.Fatalf("parallel grant status=%d, calls=%d", status, grants.Load())
	}
	close(release)
	if status := <-first; status != http.StatusSeeOther {
		t.Fatalf("first grant status=%d", status)
	}
}
