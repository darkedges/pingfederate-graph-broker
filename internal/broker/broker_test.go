package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTenant = "11111111-1111-1111-1111-111111111111"
const testObject = "22222222-2222-2222-2222-222222222222"
const testClient = "33333333-3333-3333-3333-333333333333"
const testGroup = "44444444-4444-4444-4444-444444444444"
const testScope = "openid profile User.ReadBasic.All GroupMember.Read.All"

func TestPickupDebugLogRedactsReferenceAndResponse(t *testing.T) {
	const reference = "private-reference-value"
	const responseBody = "private-upstream-body"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("REF") != reference {
			t.Error("pickup reference was not sent to PF")
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, responseBody)
	}))
	defer server.Close()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	b := New(Config{PFPickupURL: server.URL + "/pickup", PFAdapterID: "test-adapter", PFPickupUser: "test-user", PFPickupPassword: "private-password"}, nil, logger)
	if _, err := b.pickup(t.Context(), reference); err == nil {
		t.Fatal("failed pickup unexpectedly succeeded")
	}
	got := logs.String()
	if !strings.Contains(got, `"status":403`) || !strings.Contains(got, `"outcome":"http_error"`) {
		t.Fatalf("missing sanitized pickup status: %s", got)
	}
	for _, secret := range []string{reference, responseBody, "private-password", server.URL} {
		if strings.Contains(got, secret) {
			t.Fatal("pickup debug log leaked sensitive request or response data")
		}
	}
}

type fixture struct {
	b                          *Broker
	s                          *Store
	up                         *httptest.Server
	mu                         sync.Mutex
	principals                 map[string]Principal
	pickedOwner                string
	pickedExpiry               string
	refreshes, graphCalls      int
	refreshError, refreshScope string
	graphStatus                int
	badNext                    bool
	refreshOmit                bool
	lastRefresh, lastFilter    string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{principals: map[string]Principal{}, pickedOwner: "owner-1", graphStatus: 200, refreshScope: testScope}
	f.up = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.up.Close)
	key := bytes.Repeat([]byte{7}, 32)
	s, e := OpenStore(t.TempDir(), key)
	if e != nil {
		t.Fatal(e)
	}
	f.s = s
	t.Cleanup(func() { s.Close() })
	c := Config{Key: key, PFIntrospectionURL: f.up.URL + "/introspect", PFIssuer: "https://pf.example.test", Audience: "https://broker.example.test", PFClientID: "broker-rs", PFClientSecret: "introspection-secret", PFPickupURL: f.up.URL + "/pickup", PFAdapterID: "graph-import", PFPickupUser: "pickup-user", PFPickupPassword: "pickup-secret", PortalClients: []string{"portal"}, AgentClients: []string{"agent-1", "agent-2"}, TenantID: testTenant, EntraClientID: testClient, EntraClientSecret: "entra-secret", EntraTokenURL: f.up.URL + "/token", GraphBaseURL: f.up.URL + "/v1.0"}
	f.b = New(c, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.principals["owner"] = Principal{Active: true, Subject: "owner-1", ClientID: "portal", Issuer: c.PFIssuer, Audience: stringList{c.Audience}, Expires: time.Now().Add(time.Hour).Unix(), Scope: "broker.connect", Kind: "user", TokenType: "Bearer"}
	p := f.principals["owner"]
	p.Subject = "owner-2"
	f.principals["other-owner"] = p
	p.ClientID = "agent-1"
	p.Subject = "agent-1"
	p.Kind = "agent"
	p.Scope = "broker.directory.read"
	f.principals["agent"] = p
	p.ClientID = "agent-2"
	p.Subject = "agent-2"
	f.principals["other-agent"] = p
	return f
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/introspect":
		u, p, ok := r.BasicAuth()
		if !ok || u != "broker-rs" || p != "introspection-secret" || r.Method != "POST" {
			w.WriteHeader(401)
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("token_type_hint") != "access_token" {
			w.WriteHeader(400)
			return
		}
		writeJSON(w, 200, f.principals[r.PostForm.Get("token")])
	case "/pickup":
		u, p, ok := r.BasicAuth()
		if !ok || u != "pickup-user" || p != "pickup-secret" || r.Header.Get("ping.instanceId") != "graph-import" || r.URL.Query().Get("REF") != "one-time-ref" {
			w.WriteHeader(401)
			return
		}
		expiry := f.pickedExpiry
		if expiry == "" {
			expiry = "3600"
		}
		tr := map[string]any{"access_token": "initial-access", "refresh_token": "initial-refresh", "token_type": "Bearer", "expires_in": json.RawMessage(expiry), "scope": testScope}
		raw, _ := json.Marshal(tr)
		writeJSON(w, 200, map[string]any{"subject": f.pickedOwner, "entra_tid": testTenant, "entra_oid": testObject, "entra_token_response": string(raw)})
	case "/token":
		_ = r.ParseForm()
		if r.Method != "POST" || r.PostForm.Get("client_id") != testClient || r.PostForm.Get("client_secret") != "entra-secret" || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("scope") != GraphScopes {
			w.WriteHeader(400)
			return
		}
		f.refreshes++
		f.lastRefresh = r.PostForm.Get("refresh_token")
		if f.refreshError != "" {
			writeJSON(w, 400, map[string]string{"error": f.refreshError, "error_description": "sensitive-provider-details"})
			return
		}
		refresh := fmt.Sprintf("rotated-refresh-%d", f.refreshes)
		if f.refreshOmit {
			refresh = ""
		}
		writeJSON(w, 200, TokenResponse{AccessToken: fmt.Sprintf("access-%d", f.refreshes), RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: 3600, Scope: f.refreshScope})
	default:
		if !strings.HasPrefix(r.URL.Path, "/v1.0/") {
			w.WriteHeader(404)
			return
		}
		f.graphCalls++
		if r.Method != "GET" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer access-") {
			w.WriteHeader(401)
			return
		}
		f.lastFilter = r.URL.Query().Get("$filter")
		if f.graphStatus != 200 {
			writeJSON(w, f.graphStatus, map[string]string{"error": "private_graph_details"})
			return
		}
		next := ""
		if r.URL.Query().Get("$skiptoken") == "" {
			q := r.URL.Query()
			q.Set("$skiptoken", "page2")
			next = f.up.URL + r.URL.Path + "?" + q.Encode()
		}
		if f.badNext {
			next = "https://attacker.example/collect"
		}
		writeJSON(w, 200, map[string]any{"value": []map[string]string{{"id": testObject, "displayName": "Example User", "mail": "user@example.test", "secretExtraField": "must-be-dropped"}}, "@odata.nextLink": next})
	}
}
func (f *fixture) call(method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}
func jsonField(t *testing.T, w *httptest.ResponseRecorder, status int, field string) string {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d, expected=%d, body=%s", w.Code, status, w.Body.String())
	}
	var data map[string]json.RawMessage
	if e := json.Unmarshal(w.Body.Bytes(), &data); e != nil {
		t.Fatal(e)
	}
	var v string
	if e := json.Unmarshal(data[field], &v); e != nil {
		t.Fatalf("field %s: %v", field, e)
	}
	return v
}
func (f *fixture) connect(t *testing.T) string {
	t.Helper()
	id := jsonField(t, f.call("POST", "/v1/link-intents", "owner", ""), 201, "intent_id")
	return jsonField(t, f.call("POST", "/v1/link-intents/"+id+"/complete", "owner", `{"reference":"one-time-ref"}`), 201, "connection_id")
}
func (f *fixture) delegate(t *testing.T, cid string, ops []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"agent_client_id": "agent-1", "operations": ops, "expires_in_seconds": 3600})
	return jsonField(t, f.call("POST", "/v1/connections/"+cid+"/delegations", "owner", string(body)), 201, "delegation_id")
}

func TestCompleteLifecycle(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(t)
	did := f.delegate(t, cid, operations)
	for _, path := range []string{"users", "groups", "groups/" + testGroup + "/members"} {
		w := f.call("GET", "/v1/delegations/"+did+"/"+path, "agent", "")
		cursor := jsonField(t, w, 200, "next_cursor")
		if strings.Contains(w.Body.String(), "secretExtraField") || strings.Contains(w.Body.String(), "access-") {
			t.Fatal("extra provider data or tokens leaked")
		}
		w = f.call("GET", "/v1/delegations/"+did+"/"+path+"?cursor="+url.QueryEscape(cursor), "agent", "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "next_cursor") {
			t.Fatalf("pagination failed: %s", w.Body.String())
		}
	}
	if f.refreshes != 1 {
		t.Fatal("cached token was not reused")
	}
	if e := f.s.Update(func(s *State) error {
		c := s.Connections[cid]
		c.ExpiresAt = time.Now().Add(-time.Minute)
		s.Connections[cid] = c
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	w := f.call("GET", "/v1/delegations/"+did+"/users", "agent", "")
	if w.Code != 200 || f.refreshes != 2 || f.lastRefresh != "rotated-refresh-1" {
		t.Fatalf("renewal failed: %d %s", w.Code, w.Body.String())
	}
	var c Connection
	_ = f.s.View(func(s State) error { c = s.Connections[cid]; return nil })
	if c.RefreshToken != "rotated-refresh-2" {
		t.Fatal("replacement refresh token not saved")
	}
	w = f.call("GET", "/v1/connections", "owner", "")
	if strings.Contains(w.Body.String(), "refresh") || strings.Contains(w.Body.String(), "access-") {
		t.Fatal("connection metadata leaked tokens")
	}
	if w = f.call("DELETE", "/v1/connections/"+cid, "owner", ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w = f.call("GET", "/v1/delegations/"+did+"/users", "agent", ""); w.Code != 404 {
		t.Fatal("deleted connection remained accessible")
	}
}

func TestCompleteLinkWithFractionalPickupExpiry(t *testing.T) {
	f := newFixture(t)
	f.pickedExpiry = "3599.9"
	_ = f.connect(t)
	if f.refreshes != 1 || f.lastRefresh != "initial-refresh" {
		t.Fatal("fractional pickup expiry did not complete scoped Entra refresh")
	}
}

func TestIdentityAndDelegationBoundaries(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(t)
	did := f.delegate(t, cid, []string{"directory.find_users"})
	cases := []struct {
		method, path, token, body string
		want                      int
	}{
		{"GET", "/v1/delegations/" + did + "/users", "other-agent", "", 404},
		{"GET", "/v1/delegations/" + did + "/groups", "agent", "", 403},
		{"DELETE", "/v1/connections/" + cid, "other-owner", "", 404},
		{"DELETE", "/v1/delegations/" + did, "other-owner", "", 404},
		{"POST", "/v1/link-intents", "agent", "", 403},
		{"GET", "/v1/delegations/" + did + "/users", "owner", "", 403},
		{"POST", "/v1/connections/" + cid + "/delegations", "other-owner", `{"agent_client_id":"agent-1","operations":["directory.find_users"],"expires_in_seconds":3600}`, 404},
		{"POST", "/v1/connections/" + cid + "/delegations", "owner", `{"agent_client_id":"agent-1","operations":["directory.delete_user"],"expires_in_seconds":3600}`, 400},
		{"POST", "/v1/delegations/" + did + "/users", "agent", `{}`, 405},
	}
	for _, tt := range cases {
		w := f.call(tt.method, tt.path, tt.token, tt.body)
		if w.Code != tt.want {
			t.Errorf("%s %s as %s: got %d want %d", tt.method, tt.path, tt.token, w.Code, tt.want)
		}
	}
	if f.graphCalls != 0 {
		t.Fatal("denied request reached Graph")
	}
	if e := f.s.Update(func(s *State) error {
		d := s.Delegations[did]
		d.ExpiresAt = time.Now().Add(-time.Minute)
		s.Delegations[did] = d
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if w := f.call("GET", "/v1/delegations/"+did+"/users", "agent", ""); w.Code != 404 {
		t.Fatal("expired delegation accepted")
	}
}

func TestAuthenticationFailsClosed(t *testing.T) {
	f := newFixture(t)
	good := f.principals["owner"]
	cases := []struct {
		name   string
		change func(*Principal)
		want   int
	}{
		{"inactive", func(p *Principal) { p.Active = false }, 401},
		{"expired", func(p *Principal) { p.Expires = time.Now().Add(-time.Minute).Unix() }, 401},
		{"future", func(p *Principal) { p.NotBefore = time.Now().Add(time.Hour).Unix() }, 401},
		{"issuer", func(p *Principal) { p.Issuer = "https://other.test" }, 401},
		{"audience", func(p *Principal) { p.Audience = stringList{"other"} }, 401},
		{"refresh token", func(p *Principal) { p.TokenType = "" }, 401},
		{"scope", func(p *Principal) { p.Scope = "openid" }, 403},
		{"unknown client", func(p *Principal) { p.ClientID = "unknown" }, 403},
		{"missing kind", func(p *Principal) { p.Kind = "" }, 403},
		{"missing owner", func(p *Principal) { p.Subject = "" }, 403},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := good
			tt.change(&p)
			f.principals["bad"] = p
			if w := f.call("POST", "/v1/link-intents", "bad", ""); w.Code != tt.want {
				t.Fatalf("got %d want %d", w.Code, tt.want)
			}
		})
	}
	if w := f.call("POST", "/v1/link-intents", "", ""); w.Code != 401 {
		t.Fatal("missing bearer accepted")
	}
	f.up.Close()
	if w := f.call("POST", "/v1/link-intents", "owner", ""); w.Code != 503 {
		t.Fatal("introspection outage did not fail closed")
	}
}

func TestAuthenticatedSubjectEndpoint(t *testing.T) {
	f := newFixture(t)
	if got := jsonField(t, f.call("GET", "/v1/me", "owner", ""), http.StatusOK, "subject"); got != "owner-1" {
		t.Fatalf("unexpected authenticated subject %q", got)
	}
	if got := f.call("GET", "/v1/me", "agent", "").Code; got != http.StatusForbidden {
		t.Fatalf("agent obtained portal subject: %d", got)
	}
	if got := f.call("GET", "/v1/me", "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated subject lookup: %d", got)
	}
}

func TestLinkIntentBindingAndReplay(t *testing.T) {
	f := newFixture(t)
	id := jsonField(t, f.call("POST", "/v1/link-intents", "owner", ""), 201, "intent_id")
	path := "/v1/link-intents/" + id + "/complete"
	if w := f.call("POST", path, "other-owner", `{"reference":"one-time-ref"}`); w.Code != 404 {
		t.Fatal("other user completed intent")
	}
	f.pickedOwner = "owner-2"
	if w := f.call("POST", path, "owner", `{"reference":"one-time-ref"}`); w.Code != 403 {
		t.Fatal("upstream account mismatch accepted")
	}
	f.pickedOwner = "owner-1"
	if w := f.call("POST", path, "owner", `{"reference":"one-time-ref"}`); w.Code != 404 {
		t.Fatal("consumed intent replayed")
	}
	if f.refreshes != 0 {
		t.Fatal("mismatched account token refreshed")
	}
}

func TestRefreshFailureAndScopeEscalation(t *testing.T) {
	for _, scenario := range []string{"invalid_grant", "invalid_client", "broad_scope", "graph401", "omit_refresh"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			cid := f.connect(t)
			did := f.delegate(t, cid, operations)
			_ = f.s.Update(func(s *State) error {
				c := s.Connections[cid]
				c.ExpiresAt = time.Now().Add(-time.Minute)
				s.Connections[cid] = c
				return nil
			})
			want := 409
			switch scenario {
			case "invalid_grant":
				f.refreshError = "invalid_grant"
			case "invalid_client":
				f.refreshError = "invalid_client"
				want = 502
			case "broad_scope":
				f.refreshScope = testScope + " Directory.ReadWrite.All"
			case "graph401":
				f.graphStatus = 401
			case "omit_refresh":
				f.refreshOmit = true
				want = 200
			}
			w := f.call("GET", "/v1/delegations/"+did+"/users", "agent", "")
			if w.Code != want {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private_graph") || strings.Contains(w.Body.String(), "sensitive-provider") {
				t.Fatal("upstream error details leaked")
			}
			_ = f.s.View(func(s State) error {
				c := s.Connections[cid]
				if want == 409 && (c.Status != "reconnect_required" || c.RefreshToken != "") {
					t.Fatal("unusable grant retained")
				}
				if scenario == "omit_refresh" && c.RefreshToken != "rotated-refresh-1" {
					t.Fatal("refresh token lost when response omitted replacement")
				}
				if scenario == "invalid_client" && c.Status != "active" {
					t.Fatal("configuration error incorrectly revoked user connection")
				}
				return nil
			})
		})
	}
}

func TestConcurrentRefreshIsSerialised(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(t)
	did := f.delegate(t, cid, operations)
	_ = f.s.Update(func(s *State) error {
		c := s.Connections[cid]
		c.ExpiresAt = time.Now().Add(-time.Minute)
		s.Connections[cid] = c
		return nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.call("GET", "/v1/delegations/"+did+"/users", "agent", "")
			if w.Code != 200 {
				t.Errorf("concurrent request: %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if f.refreshes != 2 {
		t.Fatalf("wanted initial plus one renewal, got %d", f.refreshes)
	}
}

func TestPaginationAndQueryBoundaries(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(t)
	did := f.delegate(t, cid, operations)
	base := "/v1/delegations/" + did
	w := f.call("GET", base+"/users?prefix="+url.QueryEscape("O'Connor"), "agent", "")
	cursor := jsonField(t, w, 200, "next_cursor")
	if f.lastFilter != "startswith(displayName,'O''Connor')" {
		t.Fatal("OData string not escaped")
	}
	for _, path := range []string{base + "/groups?cursor=" + cursor, base + "/users?cursor=" + cursor + "&prefix=x", base + "/users?cursor=bad", base + "/users?$filter=true", base + "/users?prefix=x&prefix=y", base + "/groups/not-a-guid/members"} {
		if w := f.call("GET", path, "agent", ""); w.Code != 400 {
			t.Fatalf("unsafe query accepted: %s %d", path, w.Code)
		}
	}
	did2 := f.delegate(t, cid, operations)
	if w := f.call("GET", "/v1/delegations/"+did2+"/users?cursor="+cursor, "agent", ""); w.Code != 400 {
		t.Fatal("cursor crossed delegation")
	}
	f.badNext = true
	if w := f.call("GET", base+"/users", "agent", ""); w.Code != 502 {
		t.Fatal("external pagination URL accepted")
	}
	for _, raw := range []string{"https://attacker.test/v1.0/users", f.up.URL + "/v1.0/groups", f.up.URL + "/v1.0/users#fragment", strings.Replace(f.up.URL, "http://", "http://user@", 1) + "/v1.0/users"} {
		if f.b.validGraphURL(raw, "/users") {
			t.Fatal("invalid Graph target accepted")
		}
	}
}

func TestStoreEncryptionRestartAndAtomicity(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{3}, 32)
	s, e := OpenStore(dir, key)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := OpenStore(dir, key); e == nil {
		other.Close()
		t.Fatal("second process store accepted")
	}
	e = s.Update(func(st *State) error {
		st.Connections["id"] = Connection{ID: "id", RefreshToken: "very-sensitive-refresh"}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(dir, "state.enc"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte("very-sensitive")) {
		t.Fatal("plaintext token on disk")
	}
	e = s.Update(func(st *State) error { delete(st.Connections, "id"); return fmt.Errorf("abort") })
	if e == nil {
		t.Fatal("expected failed transaction")
	}
	s.Close()
	s, e = OpenStore(dir, key)
	if e != nil {
		t.Fatal(e)
	}
	_ = s.View(func(st State) error {
		if st.Connections["id"].RefreshToken != "very-sensitive-refresh" {
			t.Fatal("restart lost committed data")
		}
		return nil
	})
	s.Close()
	if bad, e := OpenStore(dir, bytes.Repeat([]byte{4}, 32)); e == nil {
		bad.Close()
		t.Fatal("wrong key accepted")
	}
	data[len(data)-1] ^= 1
	if e := os.WriteFile(filepath.Join(dir, "state.enc"), data, 0600); e != nil {
		t.Fatal(e)
	}
	if bad, e := OpenStore(dir, key); e == nil {
		bad.Close()
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestScopeAllowlist(t *testing.T) {
	for _, s := range []string{testScope, GraphScopes, "openid profile email offline_access User.Read " + GraphScopes} {
		if e := validateGraphScopes(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"", "User.Read", testScope + " Directory.Read.All", testScope + " User.ReadWrite.All", testScope + " https://other.example/User.ReadBasic.All"} {
		if validateGraphScopes(s) == nil {
			t.Fatalf("accepted scope %q", s)
		}
	}
}

func TestParsePickedTokenResponseExpiry(t *testing.T) {
	for _, tt := range []struct {
		expiry string
		want   int64
	}{
		{`3600`, 3600},
		{`"3600"`, 3600},
		{`3600.0`, 3600},
		{`3.6e3`, 3600},
		{`3599.9`, 3599},
		{`1.9`, 1},
	} {
		raw := []byte(`{"access_token":"test-access","refresh_token":"test-refresh","token_type":"Bearer","scope":"` + testScope + `","expires_in":` + tt.expiry + `}`)
		got, err := parsePickedTokenResponse(raw)
		if err != nil || got.ExpiresIn != tt.want || got.validate(true) != nil {
			t.Fatalf("valid expiry representation %s was rejected", tt.expiry)
		}
	}
	for _, expiry := range []string{`"03600"`, `"+3600"`, `"3600.0"`, `0.9`, `86400.01`, `1e309`, `["3600"]`, `true`, `"9223372036854775808"`} {
		raw := []byte(`{"access_token":"test-access","refresh_token":"test-refresh","token_type":"Bearer","scope":"` + testScope + `","expires_in":` + expiry + `}`)
		if _, err := parsePickedTokenResponse(raw); err == nil {
			t.Fatalf("invalid expiry representation %s was accepted", expiry)
		}
	}
	for _, expiry := range []string{`0`, `"0"`, `86401`, `"86401"`} {
		raw := []byte(`{"access_token":"test-access","refresh_token":"test-refresh","token_type":"Bearer","scope":"` + testScope + `","expires_in":` + expiry + `}`)
		got, err := parsePickedTokenResponse(raw)
		if err == nil && got.validate(true) == nil {
			t.Fatalf("out-of-range expiry %s passed validation", expiry)
		}
	}
}

func TestTokenResponseFormatShapeDoesNotExposeValues(t *testing.T) {
	tests := []struct {
		name, raw, want string
	}{
		{"missing", "", "missing"},
		{"null", `null`, "null"},
		{"text", `"{access_token=PRIVATE_TOKEN}"`, "string_non_json"},
		{"array text", `["PRIVATE_TOKEN"]`, "array_string_non_json"},
		{"array object", `[{"access_token":"PRIVATE_TOKEN"}]`, "array_non_string"},
		{"array multiple", `["PRIVATE_TOKEN","PRIVATE_TOKEN"]`, "array_not_singleton"},
		{"wrong expiry type", `{"expires_in":"PRIVATE_TOKEN"}`, "object_field_type_expires_in_non_decimal_string"},
		{"noncanonical expiry", `{"expires_in":"03600"}`, "object_field_type_expires_in_noncanonical_decimal_string"},
		{"fractional expiry", `{"expires_in":3600.5}`, "object_field_type_expires_in_non_integer_number"},
		{"array expiry", `{"expires_in":[3600]}`, "object_field_type_expires_in_array"},
		{"boolean expiry", `{"expires_in":true}`, "object_field_type_expires_in_boolean"},
		{"wrong access token type", `{"access_token":{"value":"PRIVATE_TOKEN"}}`, "object_field_type_access_token"},
		{"string wrapped object", `"{\"expires_in\":\"PRIVATE_TOKEN\"}"`, "string_object_field_type_expires_in_non_decimal_string"},
		{"other type", `true`, "unsupported_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenResponseFormatShape(json.RawMessage(tt.raw))
			if got != tt.want || strings.Contains(got, "PRIVATE_TOKEN") {
				t.Fatalf("format shape = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigRejectsUnsafeEndpoints(t *testing.T) {
	values := map[string]string{"TOKEN_ENCRYPTION_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "PF_ISSUER": "https://pf.test", "BROKER_AUDIENCE": "https://broker.test", "PF_INTROSPECTION_URL": "https://pf.test/as/introspect.oauth2", "PF_INTROSPECTION_CLIENT_ID": "rs", "PF_INTROSPECTION_CLIENT_SECRET": "secret", "PF_PICKUP_URL": "https://pf.test/ext/ref/pickup", "PF_SP_ADAPTER_ID": "sp", "PF_PICKUP_USER": "u", "PF_PICKUP_PASSWORD": "p", "PF_PORTAL_CLIENT_IDS": "portal", "PF_AGENT_CLIENT_IDS": "agent", "ENTRA_TENANT_ID": testTenant, "ENTRA_CLIENT_ID": testClient, "ENTRA_CLIENT_SECRET": "secret"}
	for k, v := range values {
		t.Setenv(k, v)
	}
	if _, e := LoadConfig(); e != nil {
		t.Fatal(e)
	}
	for _, endpoint := range []string{"http://pf.test/introspect", "https://u:p@pf.test/introspect", "https://pf.test/introspect?q=x", ""} {
		t.Setenv("PF_INTROSPECTION_URL", endpoint)
		if _, e := LoadConfig(); e == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
}

func TestRedirectsNeverForwardCredentials(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(200) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	r, _ := http.NewRequest("GET", source.URL, nil)
	r.Header.Set("Authorization", "Bearer secret")
	res, e := outboundClient().Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 307 || hits != 0 {
		t.Fatal("followed credential-bearing redirect")
	}
}
