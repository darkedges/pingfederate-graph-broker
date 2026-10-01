// Command demo runs a loopback-only portal with local PF, Entra, and Graph
// simulators. It never contacts an identity tenant or Microsoft Graph.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"example.com/pingfederate-graph-broker/internal/broker"
)

const (
	tenantID = "11111111-1111-1111-1111-111111111111"
	objectID = "22222222-2222-2222-2222-222222222222"
	clientID = "33333333-3333-3333-3333-333333333333"
	groupID  = "44444444-4444-4444-4444-444444444444"
	issuer   = "https://pf.demo.invalid"
	audience = "https://broker.demo.invalid"
	scopes   = "openid profile User.ReadBasic.All GroupMember.Read.All"
)

type simulator struct {
	mu                              sync.Mutex
	userToken, agentToken           string
	reference, refreshToken, access string
	base                            string
}

func secret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *simulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/introspect":
		u, p, ok := r.BasicAuth()
		if r.Method != http.MethodPost || !ok || u != "demo-resource-server" || p != "demo-introspection-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("token_type_hint") != "access_token" {
			http.Error(w, "invalid hint", http.StatusBadRequest)
			return
		}
		base := map[string]any{"active": true, "iss": issuer, "aud": audience, "exp": time.Now().Add(time.Hour).Unix(), "token_type": "Bearer"}
		switch r.PostForm.Get("token") {
		case s.userToken:
			base["sub"], base["client_id"], base["scope"], base["broker_principal_type"] = "demo-owner", "demo-portal", "broker.connect", "user"
		case s.agentToken:
			base["sub"], base["client_id"], base["scope"], base["broker_principal_type"] = "demo-agent", "demo-agent", "broker.directory.read", "agent"
		default:
			base = map[string]any{"active": false}
		}
		writeJSON(w, http.StatusOK, base)
	case "/pickup":
		u, p, ok := r.BasicAuth()
		if r.Method != http.MethodGet || !ok || u != "demo-pickup" || p != "demo-pickup-secret" || r.Header.Get("ping.instanceId") != "demo-adapter" || s.reference == "" || r.URL.Query().Get("REF") != s.reference {
			http.Error(w, "unavailable", http.StatusUnauthorized)
			return
		}
		s.reference = ""
		writeJSON(w, http.StatusOK, map[string]any{"subject": "demo-owner", "entra_tid": tenantID, "entra_oid": objectID, "entra_token_response": broker.TokenResponse{AccessToken: "unused-initial-access", RefreshToken: s.refreshToken, TokenType: "Bearer", ExpiresIn: 3600, Scope: scopes}})
	case "/token":
		_ = r.ParseForm()
		if r.Method != http.MethodPost || r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("client_id") != clientID || r.PostForm.Get("client_secret") != "demo-entra-secret" || r.PostForm.Get("scope") != broker.GraphScopes || r.PostForm.Get("refresh_token") != s.refreshToken || s.refreshToken == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		s.refreshToken, s.access = secret(), secret()
		writeJSON(w, http.StatusOK, broker.TokenResponse{AccessToken: s.access, RefreshToken: s.refreshToken, TokenType: "Bearer", ExpiresIn: 3600, Scope: scopes})
	default:
		if !strings.HasPrefix(r.URL.Path, "/v1.0/") {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+s.access || s.access == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.graph(w, r)
	}
}

func (s *simulator) graph(w http.ResponseWriter, r *http.Request) {
	var items []map[string]string
	switch r.URL.Path {
	case "/v1.0/users":
		items = []map[string]string{
			{"id": objectID, "displayName": "Alex Morgan", "mail": "alex@example.test", "userPrincipalName": "alex@example.test"},
			{"id": "55555555-5555-5555-5555-555555555555", "displayName": "Avery Chen", "mail": "avery@example.test", "userPrincipalName": "avery@example.test"},
			{"id": "66666666-6666-6666-6666-666666666666", "displayName": "Sam Rivera", "mail": "sam@example.test", "userPrincipalName": "sam@example.test"},
		}
	case "/v1.0/groups":
		items = []map[string]string{{"id": groupID, "displayName": "Engineering", "mail": "engineering@example.test"}, {"id": "77777777-7777-7777-7777-777777777777", "displayName": "Research", "mail": "research@example.test"}}
	case "/v1.0/groups/" + groupID + "/members":
		items = []map[string]string{{"id": objectID, "displayName": "Alex Morgan", "@odata.type": "#microsoft.graph.user"}, {"id": "55555555-5555-5555-5555-555555555555", "displayName": "Avery Chen", "@odata.type": "#microsoft.graph.user"}}
	default:
		http.NotFound(w, r)
		return
	}
	filter := r.URL.Query().Get("$filter")
	if filter != "" {
		if !strings.HasPrefix(filter, "startswith(displayName,'") || !strings.HasSuffix(filter, "')") {
			http.Error(w, "invalid filter", http.StatusBadRequest)
			return
		}
		prefix := strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(filter, "startswith(displayName,'"), "')"), "''", "'")
		selected := make([]map[string]string, 0, len(items))
		for _, item := range items {
			if strings.HasPrefix(strings.ToLower(item["displayName"]), strings.ToLower(prefix)) {
				selected = append(selected, item)
			}
		}
		items = selected
	}
	// Two items per simulated page make the broker's opaque cursor visible.
	page := 0
	if r.URL.Query().Get("$skiptoken") == "page2" {
		page = 1
	} else if r.URL.Query().Has("$skiptoken") {
		http.Error(w, "invalid page", http.StatusBadRequest)
		return
	}
	start := page * 2
	if start > len(items) {
		start = len(items)
	}
	end := start + 2
	if end > len(items) {
		end = len(items)
	}
	response := map[string]any{"value": items[start:end]}
	if end < len(items) {
		q := r.URL.Query()
		q.Set("$skiptoken", "page2")
		response["@odata.nextLink"] = s.base + r.URL.Path + "?" + q.Encode()
	}
	writeJSON(w, http.StatusOK, response)
}

type demo struct {
	mu                         sync.Mutex
	sim                        *simulator
	upstream                   *httptest.Server
	store                      *broker.Store
	api                        http.Handler
	connectionID, delegationID string
}

func newDemo() (*demo, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "broker-demo-")
	if err != nil {
		return nil, err
	}
	store, err := broker.OpenStore(dir, key)
	if err != nil {
		return nil, err
	}
	sim := &simulator{userToken: secret(), agentToken: secret()}
	upstream := httptest.NewServer(sim)
	sim.base = upstream.URL
	cfg := broker.Config{PFIntrospectionURL: upstream.URL + "/introspect", PFIssuer: issuer, Audience: audience, PFClientID: "demo-resource-server", PFClientSecret: "demo-introspection-secret", PFPickupURL: upstream.URL + "/pickup", PFAdapterID: "demo-adapter", PFPickupUser: "demo-pickup", PFPickupPassword: "demo-pickup-secret", PortalClients: []string{"demo-portal"}, AgentClients: []string{"demo-agent"}, TenantID: tenantID, EntraClientID: clientID, EntraClientSecret: "demo-entra-secret", EntraTokenURL: upstream.URL + "/token", GraphBaseURL: upstream.URL + "/v1.0"}
	app := broker.New(cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &demo{sim: sim, upstream: upstream, store: store, api: app.Handler()}, nil
}

func (d *demo) close() {
	d.upstream.Close()
	_ = d.store.Close()
}

func (d *demo) call(method, path, token string, body any) (int, map[string]any) {
	var input io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		input = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, input)
	r.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	d.api.ServeHTTP(w, r)
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	return w.Code, result
}

func (d *demo) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, pageHTML)
	})
	m.HandleFunc("GET /demo/state", d.state)
	m.HandleFunc("POST /demo/connect", d.connect)
	m.HandleFunc("POST /demo/delegate", d.delegate)
	m.HandleFunc("GET /demo/read", d.read)
	m.HandleFunc("POST /demo/revoke", d.revoke)
	m.HandleFunc("POST /demo/disconnect", d.disconnect)
	m.Handle("/v1/", d.api)
	m.Handle("/healthz", d.api)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/demo/") {
			if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "same_origin_json_required"})
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "same_origin_required"})
				return
			}
		}
		m.ServeHTTP(w, r)
	})
}

func (d *demo) state(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	status, result := d.call(http.MethodGet, "/v1/connections", d.sim.userToken, nil)
	if status != 200 {
		writeJSON(w, status, result)
		return
	}
	writeJSON(w, 200, map[string]any{"connections": result["items"], "delegation_active": d.delegationID != "", "delegation_id": d.delegationID, "sample_group_id": groupID})
}

func (d *demo) connect(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connectionID != "" {
		writeJSON(w, 409, map[string]string{"error": "already_connected"})
		return
	}
	status, intent := d.call(http.MethodPost, "/v1/link-intents", d.sim.userToken, nil)
	if status != 201 {
		writeJSON(w, status, intent)
		return
	}
	ref := secret()
	d.sim.mu.Lock()
	d.sim.reference, d.sim.refreshToken, d.sim.access = ref, secret(), ""
	d.sim.mu.Unlock()
	status, connection := d.call(http.MethodPost, "/v1/link-intents/"+fmt.Sprint(intent["intent_id"])+"/complete", d.sim.userToken, map[string]string{"reference": ref})
	if status == 201 {
		d.connectionID = fmt.Sprint(connection["connection_id"])
	}
	writeJSON(w, status, connection)
}

func (d *demo) delegate(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connectionID == "" {
		writeJSON(w, 409, map[string]string{"error": "connect_first"})
		return
	}
	if d.delegationID != "" {
		writeJSON(w, 409, map[string]string{"error": "already_delegated"})
		return
	}
	status, result := d.call(http.MethodPost, "/v1/connections/"+d.connectionID+"/delegations", d.sim.userToken, map[string]any{"agent_client_id": "demo-agent", "operations": []string{"directory.find_users", "directory.find_groups", "directory.list_group_members"}, "expires_in_seconds": 3600})
	if status == 201 {
		d.delegationID = fmt.Sprint(result["delegation_id"])
	}
	writeJSON(w, status, result)
}

func (d *demo) read(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.delegationID == "" {
		writeJSON(w, 409, map[string]string{"error": "delegate_first"})
		return
	}
	var path string
	switch r.URL.Query().Get("kind") {
	case "users":
		path = "users"
	case "groups":
		path = "groups"
	case "members":
		path = "groups/" + groupID + "/members"
	default:
		writeJSON(w, 400, map[string]string{"error": "invalid_kind"})
		return
	}
	q := url.Values{}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		q.Set("cursor", cursor)
	} else if prefix := r.URL.Query().Get("prefix"); prefix != "" && path != "groups/"+groupID+"/members" {
		q.Set("prefix", prefix)
	}
	target := "/v1/delegations/" + d.delegationID + "/" + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	status, result := d.call(http.MethodGet, target, d.sim.agentToken, nil)
	writeJSON(w, status, result)
}

func (d *demo) revoke(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.delegationID == "" {
		writeJSON(w, 409, map[string]string{"error": "no_delegation"})
		return
	}
	status, result := d.call(http.MethodDelete, "/v1/delegations/"+d.delegationID, d.sim.userToken, nil)
	if status == 204 {
		d.delegationID = ""
		writeJSON(w, 200, map[string]string{"status": "revoked"})
		return
	}
	writeJSON(w, status, result)
}

func (d *demo) disconnect(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.connectionID == "" {
		writeJSON(w, 409, map[string]string{"error": "no_connection"})
		return
	}
	status, result := d.call(http.MethodDelete, "/v1/connections/"+d.connectionID, d.sim.userToken, nil)
	if status == 204 {
		d.connectionID, d.delegationID = "", ""
		writeJSON(w, 200, map[string]string{"status": "disconnected"})
		return
	}
	writeJSON(w, status, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func main() {
	d, err := newDemo()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer d.close()
	addr := os.Getenv("DEMO_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8081"
	}
	srv := &http.Server{Addr: addr, Handler: d.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	fmt.Printf("Local directory demo listening at http://%s\n", addr)
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}
}
