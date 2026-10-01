package broker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/fnv"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var operations = []string{"directory.find_users", "directory.find_groups", "directory.list_group_members"}
var opaqueID = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

type Broker struct {
	cfg   Config
	store *Store
	http  *http.Client
	log   *slog.Logger
	locks [64]sync.Mutex
}

func New(cfg Config, store *Store, logger *slog.Logger) *Broker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Broker{cfg: cfg, store: store, http: outboundClient(), log: logger}
}
func (b *Broker) connectionLock(id string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return &b.locks[h.Sum32()%uint32(len(b.locks))]
}

func (b *Broker) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /v1/me", b.user(func(w http.ResponseWriter, _ *http.Request, p Principal) error {
		writeJSON(w, http.StatusOK, map[string]string{"subject": p.Subject})
		return nil
	}))
	m.HandleFunc("POST /v1/link-intents", b.user(b.beginLink))
	m.HandleFunc("POST /v1/link-intents/{intent}/complete", b.user(b.completeLink))
	m.HandleFunc("POST /v1/connections/saml", b.user(b.samlConnect))
	m.HandleFunc("GET /v1/connections", b.user(b.listConnections))
	m.HandleFunc("DELETE /v1/connections/{connection}", b.user(b.deleteConnection))
	m.HandleFunc("POST /v1/connections/{connection}/delegations", b.user(b.createDelegation))
	m.HandleFunc("DELETE /v1/delegations/{delegation}", b.user(b.deleteDelegation))
	m.HandleFunc("GET /v1/delegations/{delegation}/users", b.agent("directory.find_users"))
	m.HandleFunc("GET /v1/delegations/{delegation}/groups", b.agent("directory.find_groups"))
	m.HandleFunc("GET /v1/delegations/{delegation}/groups/{group}/members", b.agent("directory.list_group_members"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Request-ID", newID())
		// No cookie authentication or CORS: the existing portal backend calls this API.
		if len(r.RequestURI) > 16384 {
			writeError(w, fail(414, "uri_too_long"))
			return
		}
		m.ServeHTTP(w, r)
	})
}

type userHandler func(http.ResponseWriter, *http.Request, Principal) error

func (b *Broker) user(fn userHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, e := b.authenticate(r, "user", "broker.connect")
		if e == nil {
			e = fn(w, r, p)
		}
		if e != nil {
			writeError(w, e)
		}
		b.audit(r, p, "connection_management", e)
	}
}
func (b *Broker) audit(r *http.Request, p Principal, operation string, e error) {
	outcome := "success"
	if e != nil {
		var a *apiError
		if errors.As(e, &a) {
			outcome = a.code
		} else {
			outcome = "internal_error"
		}
	}
	// Intentionally omit URLs, bodies, search terms, reference values, and tokens.
	b.log.Info("broker_request", "client_id", p.ClientID, "operation", operation, "outcome", outcome, "delegation_id", r.PathValue("delegation"))
}
func (b *Broker) beginLink(w http.ResponseWriter, r *http.Request, p Principal) error {
	intent := Intent{ID: newID(), Owner: p.Subject, ExpiresAt: time.Now().Add(5 * time.Minute)}
	e := b.store.Update(func(s *State) error {
		for id, i := range s.Intents {
			if i.Owner == p.Subject || time.Now().After(i.ExpiresAt) {
				delete(s.Intents, id)
			}
		}
		s.Intents[intent.ID] = intent
		return nil
	})
	if e != nil {
		return e
	}
	writeJSON(w, 201, map[string]any{"intent_id": intent.ID, "expires_at": intent.ExpiresAt})
	return nil
}
func (b *Broker) completeLink(w http.ResponseWriter, r *http.Request, p Principal) error {
	var input struct {
		Reference string `json:"reference"`
	}
	if e := decodeBody(w, r, &input); e != nil {
		return e
	}
	id := r.PathValue("intent")
	// Consume before calling pickup. Retry by starting a new link flow after a failure.
	e := b.store.Update(func(s *State) error {
		i, ok := s.Intents[id]
		if !ok || i.Owner != p.Subject || !time.Now().Before(i.ExpiresAt) {
			return fail(404, "link_intent_not_found")
		}
		delete(s.Intents, id)
		return nil
	})
	if e != nil {
		return e
	}
	picked, e := b.pickup(r.Context(), input.Reference)
	if e != nil {
		return e
	}
	if picked.Owner != p.Subject {
		return fail(403, "account_link_identity_mismatch")
	}
	c := Connection{ID: newID(), Owner: p.Subject, TenantID: b.cfg.TenantID, ObjectID: picked.ObjectID, ClientID: b.cfg.EntraClientID, RefreshToken: picked.Tokens.RefreshToken, CreatedAt: time.Now(), Status: "active"}
	// Validate the refresh token against our configured Entra client and obtain explicitly
	// requested read scopes before accepting the connection. Never trust arbitrary imports.
	t, e := b.refresh(r.Context(), c)
	if e != nil {
		return e
	}
	applyTokens(&c, t)
	e = b.store.Update(func(s *State) error {
		count := 0
		for _, existing := range s.Connections {
			if existing.Owner == p.Subject {
				count++
			}
		}
		if count >= 10 {
			return fail(409, "connection_limit_reached")
		}
		s.Connections[c.ID] = c
		return nil
	})
	if e != nil {
		return e
	}
	writeJSON(w, 201, connectionSummary(c))
	return nil
}
func connectionSummary(c Connection) map[string]any {
	return map[string]any{"connection_id": c.ID, "tenant_id": c.TenantID, "object_id": c.ObjectID, "status": c.Status, "scopes": c.Scope, "created_at": c.CreatedAt, "expires_at": c.ExpiresAt, "mode": c.Mode}
}
func (b *Broker) listConnections(w http.ResponseWriter, r *http.Request, p Principal) error {
	items := []map[string]any{}
	if e := b.store.View(func(s State) error {
		for _, c := range s.Connections {
			if c.Owner == p.Subject {
				items = append(items, connectionSummary(c))
			}
		}
		return nil
	}); e != nil {
		return e
	}
	writeJSON(w, 200, map[string]any{"items": items})
	return nil
}
func (b *Broker) deleteConnection(w http.ResponseWriter, r *http.Request, p Principal) error {
	id := r.PathValue("connection")
	lock := b.connectionLock(id)
	lock.Lock()
	defer lock.Unlock()
	e := b.store.Update(func(s *State) error {
		c, ok := s.Connections[id]
		if !ok || c.Owner != p.Subject {
			return fail(404, "connection_not_found")
		}
		delete(s.Connections, id)
		for id, d := range s.Delegations {
			if d.ConnectionID == c.ID {
				delete(s.Delegations, id)
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	w.WriteHeader(204)
	return nil
}
func (b *Broker) createDelegation(w http.ResponseWriter, r *http.Request, p Principal) error {
	var input struct {
		AgentClientID string   `json:"agent_client_id"`
		Operations    []string `json:"operations"`
		ExpiresIn     int64    `json:"expires_in_seconds"`
	}
	if e := decodeBody(w, r, &input); e != nil {
		return e
	}
	if !contains(b.cfg.AgentClients, input.AgentClientID) || input.ExpiresIn < 60 || input.ExpiresIn > 604800 || len(input.Operations) < 1 || len(input.Operations) > 3 {
		return fail(400, "invalid_delegation")
	}
	seen := map[string]bool{}
	for _, op := range input.Operations {
		if !contains(operations, op) || seen[op] {
			return fail(400, "invalid_operation")
		}
		seen[op] = true
	}
	d := Delegation{ID: newID(), ConnectionID: r.PathValue("connection"), Owner: p.Subject, AgentClientID: input.AgentClientID, Operations: input.Operations, ExpiresAt: time.Now().Add(time.Duration(input.ExpiresIn) * time.Second)}
	e := b.store.Update(func(s *State) error {
		c, ok := s.Connections[d.ConnectionID]
		if !ok || c.Owner != p.Subject {
			return fail(404, "connection_not_found")
		}
		if c.Status != "active" {
			return fail(409, "reconnect_required")
		}
		if c.Mode == "saml" {
			if !c.ExpiresAt.After(time.Now().Add(90 * time.Second)) {
				return fail(409, "reconnect_required")
			}
			if d.ExpiresAt.After(c.ExpiresAt) {
				d.ExpiresAt = c.ExpiresAt
			}
		}
		count := 0
		for id, old := range s.Delegations {
			if !time.Now().Before(old.ExpiresAt) {
				delete(s.Delegations, id)
			} else if old.ConnectionID == c.ID {
				count++
			}
		}
		if count >= 20 {
			return fail(409, "delegation_limit_reached")
		}
		s.Delegations[d.ID] = d
		return nil
	})
	if e != nil {
		return e
	}
	writeJSON(w, 201, map[string]any{"delegation_id": d.ID, "expires_at": d.ExpiresAt, "operations": d.Operations})
	return nil
}
func (b *Broker) deleteDelegation(w http.ResponseWriter, r *http.Request, p Principal) error {
	id := r.PathValue("delegation")
	var cid string
	if e := b.store.View(func(s State) error {
		d, ok := s.Delegations[id]
		if !ok || d.Owner != p.Subject {
			return fail(404, "delegation_not_found")
		}
		cid = d.ConnectionID
		return nil
	}); e != nil {
		return e
	}
	lock := b.connectionLock(cid)
	lock.Lock()
	defer lock.Unlock()
	if e := b.store.Update(func(s *State) error {
		d, ok := s.Delegations[id]
		if !ok || d.Owner != p.Subject {
			return fail(404, "delegation_not_found")
		}
		delete(s.Delegations, id)
		return nil
	}); e != nil {
		return e
	}
	w.WriteHeader(204)
	return nil
}
func (b *Broker) agent(operation string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, e := b.authenticate(r, "agent", "broker.directory.read")
		var page Page
		if e == nil {
			page, e = b.directory(r, p, operation)
		}
		if e != nil {
			writeError(w, e)
		} else {
			writeJSON(w, 200, page)
		}
		b.audit(r, p, operation, e)
	}
}
func (b *Broker) authorise(id, client, operation string) (Delegation, Connection, error) {
	var d Delegation
	var c Connection
	e := b.store.View(func(s State) error {
		var ok bool
		d, ok = s.Delegations[id]
		if !ok || d.AgentClientID != client || !time.Now().Before(d.ExpiresAt) {
			return fail(404, "delegation_not_found")
		}
		if !contains(d.Operations, operation) {
			return fail(403, "operation_not_delegated")
		}
		c, ok = s.Connections[d.ConnectionID]
		validConnector := c.Mode == "" && c.TenantID == b.cfg.TenantID && c.ClientID == b.cfg.EntraClientID
		validSAML := c.Mode == "saml" && b.cfg.SAML.Enabled() && c.TenantID == b.cfg.SAML.TenantID && c.ClientID == b.cfg.SAML.OBOClientID && c.ObjectID == b.cfg.SAML.ExpectedEntraOID && c.Owner == b.cfg.SAML.ExpectedPFSubject
		if !ok || c.Owner != d.Owner || (!validConnector && !validSAML) {
			return fail(404, "connection_not_found")
		}
		if c.Status != "active" {
			return fail(409, "reconnect_required")
		}
		if c.Mode == "saml" && !time.Now().Before(c.ExpiresAt) {
			return fail(409, "reconnect_required")
		}
		return nil
	})
	return d, c, e
}
func (b *Broker) directory(r *http.Request, p Principal, operation string) (Page, error) {
	var result Page
	id := r.PathValue("delegation")
	if !opaqueID.MatchString(id) {
		return result, fail(404, "delegation_not_found")
	}
	d, _, e := b.authorise(id, p.ClientID, operation)
	if e != nil {
		return result, e
	}
	lock := b.connectionLock(d.ConnectionID)
	lock.Lock()
	defer lock.Unlock()
	d, c, e := b.authorise(id, p.ClientID, operation)
	if e != nil {
		return result, e
	}
	target, path, e := b.graphTarget(r, d, operation)
	if e != nil {
		return result, e
	}
	if !c.ExpiresAt.After(time.Now().Add(90 * time.Second)) {
		if c.Mode == "saml" {
			return result, fail(409, "reconnect_required")
		}
		t, err := b.refresh(r.Context(), c)
		if err != nil {
			if isReconnect(err) {
				if se := b.markReconnect(c.ID); se != nil {
					return result, se
				}
			}
			return result, err
		}
		applyTokens(&c, t)
		if e = b.store.Update(func(s *State) error { s.Connections[c.ID] = c; return nil }); e != nil {
			return result, e
		}
	}
	page, e := b.graphGET(r.Context(), target, c.AccessToken)
	if e != nil {
		if isReconnect(e) {
			if se := b.markReconnect(c.ID); se != nil {
				return result, se
			}
		}
		return result, e
	}
	result.Items = page.Value
	if page.NextLink != "" {
		if !b.validGraphURL(page.NextLink, path) {
			return Page{}, fail(502, "invalid_graph_pagination")
		}
		cursor := cursorData{URL: page.NextLink, Path: path, Delegation: id, Expires: time.Now().Add(15 * time.Minute).Unix()}
		raw, _ := json.Marshal(cursor)
		raw, e = b.store.seal(raw, "graph-cursor-v1")
		if e != nil {
			return Page{}, e
		}
		result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return result, nil
}
func applyTokens(c *Connection, t TokenResponse) {
	c.AccessToken = t.AccessToken
	if t.RefreshToken != "" {
		c.RefreshToken = t.RefreshToken
	}
	c.Scope = t.Scope
	c.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	c.Status = "active"
}
func isReconnect(e error) bool {
	var a *apiError
	return errors.As(e, &a) && (a.code == "reconnect_required" || a.code == "unexpected_entra_permissions")
}
func (b *Broker) markReconnect(id string) error {
	return b.store.Update(func(s *State) error {
		c, ok := s.Connections[id]
		if !ok {
			return fail(404, "connection_not_found")
		}
		c.Status = "reconnect_required"
		c.AccessToken = ""
		c.RefreshToken = ""
		s.Connections[id] = c
		return nil
	})
}

type cursorData struct {
	URL, Path, Delegation string
	Expires               int64
}

func (b *Broker) validGraphURL(raw, path string) bool {
	u, e := url.Parse(raw)
	base, be := url.Parse(b.cfg.GraphBaseURL)
	return e == nil && be == nil && u.Scheme == base.Scheme && u.Host == base.Host && u.User == nil && u.Fragment == "" && u.Path == base.Path+path && u.RawPath == "" && len(raw) <= 12000
}
func (b *Broker) graphTarget(r *http.Request, d Delegation, operation string) (string, string, error) {
	path := "/users"
	fields := "id,displayName,mail,userPrincipalName"
	switch operation {
	case "directory.find_groups":
		path = "/groups"
		fields = "id,displayName,mail"
	case "directory.list_group_members":
		g := r.PathValue("group")
		if !guid.MatchString(g) {
			return "", "", fail(400, "invalid_group_id")
		}
		path = "/groups/" + g + "/members"
		fields = "id,displayName"
	case "directory.find_users":
	default:
		return "", "", fail(403, "operation_not_allowed")
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return "", "", fail(400, "invalid_query")
	}
	for k, vs := range q {
		if (k != "prefix" && k != "cursor") || len(vs) != 1 {
			return "", "", fail(400, "unsupported_query_parameter")
		}
	}
	if cur := q.Get("cursor"); cur != "" {
		if q.Has("prefix") {
			return "", "", fail(400, "cursor_and_prefix_are_exclusive")
		}
		raw, e := base64.RawURLEncoding.DecodeString(cur)
		if e != nil {
			return "", "", fail(400, "invalid_cursor")
		}
		raw, e = b.store.open(raw, "graph-cursor-v1")
		if e != nil {
			return "", "", fail(400, "invalid_cursor")
		}
		var c cursorData
		if json.Unmarshal(raw, &c) != nil || c.Delegation != d.ID || c.Path != path || c.Expires <= time.Now().Unix() || !b.validGraphURL(c.URL, path) {
			return "", "", fail(400, "invalid_cursor")
		}
		return c.URL, path, nil
	}
	prefix := q.Get("prefix")
	if len(prefix) > 100 || strings.ContainsAny(prefix, "\x00\r\n") || operation == "directory.list_group_members" && q.Has("prefix") {
		return "", "", fail(400, "invalid_prefix")
	}
	query := url.Values{"$select": {fields}, "$top": {"25"}}
	if prefix != "" {
		query.Set("$filter", "startswith(displayName,'"+strings.ReplaceAll(prefix, "'", "''")+"')")
	}
	return b.cfg.GraphBaseURL + path + "?" + query.Encode(), path, nil
}
