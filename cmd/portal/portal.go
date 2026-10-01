package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const loginCookie = "portal_login"
const sessionCookie = "portal_session"

type loginAttempt struct {
	state, verifier string
	expires         time.Time
}
type session struct {
	token, csrf, intent, subject string
	expires, intentExpires       time.Time
	busy, connectFailed          bool
	connectionID                 string
	delegationID                 string
	delegationConnectionID       string
	delegationExpires            time.Time
	delegationOps                []string
	delegationBusy               bool
}
type portal struct {
	c        config
	client   *http.Client
	log      *slog.Logger
	mu       sync.Mutex
	logins   map[string]loginAttempt
	sessions map[string]*session
}

func newPortal(c config, logger *slog.Logger) *portal {
	if logger == nil {
		logger = slog.Default()
	}
	if c.pfBrowserURL == nil {
		c.pfBrowserURL = c.pfURL
	}
	return &portal{c: c, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, log: logger, logins: make(map[string]loginAttempt), sessions: make(map[string]*session)}
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func same(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

func (p *portal) handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /", p.app)
	m.HandleFunc("GET /legacy", p.home)
	m.Handle("GET /_next/", p.assets())
	m.HandleFunc("GET /api/session", p.apiSession)
	m.HandleFunc("GET /api/connections", p.apiConnections)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	m.HandleFunc("GET /auth/login", p.login)
	m.HandleFunc("GET /auth/callback", p.callback)
	m.HandleFunc("GET /auth/reference-callback", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Reference must use Form POST", http.StatusMethodNotAllowed)
	})
	m.HandleFunc("POST /connect", p.connect)
	m.HandleFunc("POST /connect/saml", p.connectSAML)
	m.HandleFunc("GET /connect/continue", p.continueConnect)
	m.HandleFunc("POST /auth/reference-callback", p.referenceCallback)
	m.HandleFunc("GET /connections", p.connections)
	m.HandleFunc("POST /delegations", p.grantDelegation)
	m.HandleFunc("POST /delegations/revoke", p.revokeDelegation)
	m.HandleFunc("POST /connections/disconnect", p.disconnect)
	m.HandleFunc("POST /directory/read", p.readDirectory)
	m.HandleFunc("POST /logout", p.logout)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// Form POSTs need a non-null Origin for the CSRF origin check. Send
		// only the origin as Referer, never OAuth codes or query parameters.
		w.Header().Set("Referrer-Policy", "origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		m.ServeHTTP(w, r)
	})
}

func cookie(w http.ResponseWriter, name, value string, maxAge int, site http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: site, MaxAge: maxAge})
}

func (p *portal) current(r *http.Request) (string, *session) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[c.Value]
	if s == nil {
		return "", nil
	}
	if !time.Now().Before(s.expires) {
		delete(p.sessions, c.Value)
		return "", nil
	}
	if s.intent != "" && !time.Now().Before(s.intentExpires) {
		s.intent = ""
		s.intentExpires = time.Time{}
	}
	if s.delegationID != "" && !time.Now().Before(s.delegationExpires) {
		s.delegationID = ""
		s.delegationConnectionID = ""
		s.delegationExpires = time.Time{}
		s.delegationOps = nil
	}
	copy := *s
	copy.delegationOps = append([]string(nil), s.delegationOps...)
	return c.Value, &copy
}

func (p *portal) pruneLocked() {
	now := time.Now()
	for id, attempt := range p.logins {
		if !now.Before(attempt.expires) {
			delete(p.logins, id)
		}
	}
	for id, s := range p.sessions {
		if !now.Before(s.expires) {
			delete(p.sessions, id)
		}
	}
}

var homeHTML = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Directory portal</title>
{{if .Refresh}}<meta http-equiv="refresh" content="3">{{end}}
<style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem}button,a{font:inherit;padding:.5rem}.note{color:#555}progress{display:block;width:100%;max-width:24rem;margin:1rem 0}</style>
<h1>Directory portal</h1>
{{if .SignedIn}}
<p>Signed in to PingFederate.</p>
{{if .Connected}}<p>Microsoft connection created: <code>{{.Connected}}</code></p>{{end}}
<p><a href="/connections">Manage connections and directory reads</a></p>
{{if .Busy}}
<p role="status">Connecting to Microsoft. This page will update when the connection finishes.</p>
<progress aria-label="Connecting to Microsoft"></progress>
{{else if .Pending}}
<p role="status">Waiting for Microsoft sign-in. Your connection request is still active.</p>
<p><a href="{{.StartURL}}">Continue Microsoft sign-in</a></p>
{{else if .CanConnect}}
{{if .Failed}}<p role="alert">Connection failed. You can try again.</p>{{end}}
<form method="post" action="/connect"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Connect Microsoft</button></form>
{{else}}<p class="note">Connect is unavailable until the PF browser journey URL is configured.</p>{{end}}
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Sign out</button></form>
{{else}}<p><a href="/auth/login">Sign in with PingFederate</a></p>{{end}}
<p class="note">This local portal keeps PF access tokens on the server. Signing out here does not revoke a saved connection or delegation.</p></html>`))

var continueHTML = template.Must(template.New("continue").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Continue Microsoft sign-in</title>
<meta http-equiv="refresh" content="1;url={{.}}">
<style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;padding:0 1rem}</style>
<h1>Continue Microsoft sign-in</h1>
<p>Opening PingFederate for Microsoft sign-in…</p>
<p><a href="{{.}}">Continue Microsoft sign-in</a> if the page does not open automatically.</p>
</html>`))

var logoutHTML = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Signing out</title>
<meta http-equiv="refresh" content="0;url={{.}}">
<main><p>Signed out of the portal. Continuing to PingFederate sign-out…</p>
<p><a href="{{.}}">Continue to PingFederate sign-out</a></p></main></html>`))

func (p *portal) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/legacy" {
		http.NotFound(w, r)
		return
	}
	_, s := p.current(r)
	d := struct {
		SignedIn, CanConnect, Busy, Pending, Failed, Refresh bool
		CSRF, Connected                                      string
		StartURL                                             string
	}{}
	if s != nil {
		d.SignedIn = true
		d.CanConnect = p.c.startURL != nil && p.c.referenceSubject != "" && s.subject == p.c.referenceSubject
		d.CSRF = s.csrf
		d.Connected = s.connectionID
		d.Busy = s.busy
		d.Pending = s.intent != ""
		d.Failed = s.connectFailed
		d.Refresh = d.Busy || d.Pending
		if d.Pending {
			d.StartURL = "/connect/continue"
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeHTML.Execute(w, d)
}

func (p *portal) login(w http.ResponseWriter, r *http.Request) {
	verifier, state, key := random(), random(), random()
	p.mu.Lock()
	p.pruneLocked()
	p.logins[key] = loginAttempt{state: state, verifier: verifier, expires: time.Now().Add(5 * time.Minute)}
	p.mu.Unlock()
	cookie(w, loginCookie, key, 300, http.SameSiteLaxMode)
	u := *p.c.pfBrowserURL
	u.Path = "/as/authorization.oauth2"
	q := url.Values{"response_type": {"code"}, "client_id": {p.c.clientID}, "scope": {"broker.connect"}, "redirect_uri": {origin(p.c.publicURL) + "/auth/callback"}, "state": {state}, "code_challenge_method": {"S256"}}
	h := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(h[:]))
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (p *portal) callback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(loginCookie)
	if err != nil {
		http.Error(w, "Sign-in session missing", 400)
		return
	}
	p.mu.Lock()
	attempt, ok := p.logins[c.Value]
	delete(p.logins, c.Value)
	p.mu.Unlock()
	cookie(w, loginCookie, "", -1, http.SameSiteLaxMode)
	if !ok || time.Now().After(attempt.expires) || !same(attempt.state, r.URL.Query().Get("state")) || r.URL.Query().Get("code") == "" || r.URL.Query().Get("error") != "" {
		http.Error(w, "Sign-in rejected; start again", 400)
		return
	}
	token, lifetime, err := p.exchange(r, r.URL.Query().Get("code"), attempt.verifier)
	if err != nil {
		http.Error(w, "PingFederate sign-in failed", 502)
		return
	}
	subject, err := p.authenticatedSubject(r.Context(), token)
	if err != nil {
		http.Error(w, "Could not verify sign-in identity", 502)
		return
	}
	id := random()
	p.mu.Lock()
	p.pruneLocked()
	if old, err := r.Cookie(sessionCookie); err == nil {
		delete(p.sessions, old.Value)
	}
	p.sessions[id] = &session{token: token, csrf: random(), subject: subject, expires: time.Now().Add(lifetime)}
	p.mu.Unlock()
	cookie(w, sessionCookie, id, int(lifetime.Seconds()), http.SameSiteNoneMode)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *portal) exchange(r *http.Request, code, verifier string) (string, time.Duration, error) {
	u := *p.c.pfURL
	u.Path = "/as/token.oauth2"
	v := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {origin(p.c.publicURL) + "/auth/callback"}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u.String(), strings.NewReader(v.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.c.clientID, p.c.clientSecret)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", 0, errors.New("PF token exchange rejected")
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&out); err != nil {
		return "", 0, err
	}
	if out.AccessToken == "" || !strings.EqualFold(out.TokenType, "Bearer") || out.ExpiresIn < 1 {
		return "", 0, errors.New("invalid PF token response")
	}
	lifetime := time.Duration(out.ExpiresIn) * time.Second
	if lifetime > 30*time.Minute {
		lifetime = 30 * time.Minute
	}
	return out.AccessToken, lifetime, nil
}

func (p *portal) authenticatedSubject(ctx context.Context, token string) (string, error) {
	u := *p.c.brokerURL
	u.Path = "/v1/me"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("broker rejected portal identity")
	}
	var out struct {
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&out); err != nil || out.Subject == "" {
		return "", errors.New("invalid broker identity response")
	}
	return out.Subject, nil
}

func (p *portal) connect(w http.ResponseWriter, r *http.Request) {
	if p.c.startURL == nil || p.c.referenceSubject == "" {
		http.Error(w, "PF connection journey is not configured", 503)
		return
	}
	id, s := p.current(r)
	if s == nil {
		http.Error(w, "Sign in first", 401)
		return
	}
	if s.subject != p.c.referenceSubject {
		http.Error(w, "Connection method unavailable for this account", http.StatusForbidden)
		return
	}
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin(p.c.publicURL) {
		http.Error(w, "Invalid origin", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !same(r.PostForm.Get("csrf"), s.csrf) {
		http.Error(w, "Invalid form", 403)
		return
	}
	p.mu.Lock()
	live := p.sessions[id]
	if live == nil || live.busy || live.intent != "" {
		p.mu.Unlock()
		http.Error(w, "Connection already in progress", 409)
		return
	}
	live.busy = true
	live.connectFailed = false
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if live := p.sessions[id]; live != nil {
			live.busy = false
		}
		p.mu.Unlock()
	}()
	var out struct {
		IntentID  string    `json:"intent_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := p.broker(r.Context(), s.token, http.MethodPost, "/v1/link-intents", nil, &out); err != nil || out.IntentID == "" || !time.Now().Before(out.ExpiresAt) || strings.ContainsAny(out.IntentID, "/?#") {
		p.log.Debug("reference_intent_failed")
		http.Error(w, "Could not start connection", 502)
		return
	}
	p.mu.Lock()
	if live := p.sessions[id]; live != nil {
		live.intent, live.intentExpires = out.IntentID, out.ExpiresAt
	}
	p.mu.Unlock()
	p.log.Debug("reference_intent_created")
	// End the form navigation on this origin. A separate document initiates
	// the PF journey, so form-action 'self' cannot block the cross-origin hop.
	http.Redirect(w, r, "/connect/continue", http.StatusSeeOther)
}

func (p *portal) connectSAML(w http.ResponseWriter, r *http.Request) {
	if !p.c.samlConnectEnabled || p.c.samlSubject == "" {
		http.Error(w, "SAML connection is not configured", 503)
		return
	}
	id, s := p.current(r)
	if s == nil {
		http.Error(w, "Sign in first", 401)
		return
	}
	if s.subject != p.c.samlSubject {
		http.Error(w, "Connection method unavailable for this account", http.StatusForbidden)
		return
	}
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin(p.c.publicURL) {
		http.Error(w, "Invalid origin", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !same(r.PostForm.Get("csrf"), s.csrf) {
		http.Error(w, "Invalid form", 403)
		return
	}
	p.mu.Lock()
	live := p.sessions[id]
	if live == nil || live.busy || live.intent != "" {
		p.mu.Unlock()
		http.Error(w, "Connection already in progress", 409)
		return
	}
	live.busy, live.connectFailed = true, false
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if live := p.sessions[id]; live != nil {
			live.busy = false
		}
		p.mu.Unlock()
	}()
	var out struct {
		ConnectionID string `json:"connection_id"`
	}
	if err := p.broker(r.Context(), s.token, http.MethodPost, "/v1/connections/saml", nil, &out); err != nil || out.ConnectionID == "" {
		p.mu.Lock()
		if live := p.sessions[id]; live != nil {
			live.connectFailed = true
		}
		p.mu.Unlock()
		http.Error(w, "SAML connection failed", 502)
		return
	}
	p.mu.Lock()
	if live := p.sessions[id]; live != nil {
		live.connectionID = out.ConnectionID
	}
	p.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *portal) continueConnect(w http.ResponseWriter, r *http.Request) {
	_, s := p.current(r)
	if p.c.startURL == nil || s == nil || s.subject != p.c.referenceSubject || s.intent == "" || s.busy {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = continueHTML.Execute(w, p.c.startURL.String())
}

func (p *portal) referenceCallback(w http.ResponseWriter, r *http.Request) {
	p.log.Debug("reference_callback_received")
	if r.URL.RawQuery != "" {
		p.log.Debug("reference_callback_rejected", "reason", "query_present")
		http.Error(w, "Reference must use Form POST", 400)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		p.log.Debug("reference_callback_rejected", "reason", "content_type")
		http.Error(w, "Invalid content type", 415)
		return
	}
	if r.Header.Get("Origin") != origin(p.c.pfBrowserURL) {
		p.log.Debug("reference_callback_rejected", "reason", "origin")
		http.Error(w, "Invalid origin", 403)
		return
	}
	id, s := p.current(r)
	if s == nil {
		p.log.Debug("reference_callback_rejected", "reason", "session_missing")
		http.Error(w, "Sign-in session missing", 401)
		return
	}
	if p.c.referenceSubject == "" || s.subject != p.c.referenceSubject {
		p.log.Debug("reference_callback_rejected", "reason", "subject_not_allowed")
		http.Error(w, "Connection method unavailable for this account", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		p.log.Debug("reference_callback_rejected", "reason", "invalid_form")
		http.Error(w, "Invalid form", 400)
		return
	}
	expectedTargetResource := origin(p.c.publicURL) + "/auth/reference-callback"
	if reason := referenceFormFailure(r.PostForm, expectedTargetResource); reason != "" {
		// Only a fixed reason and a count are logged. Form keys and values can
		// contain reference IDs or other user-controlled data.
		p.log.Debug("reference_callback_rejected", "reason", reason, "form_field_count", len(r.PostForm))
		http.Error(w, "Invalid reference", 400)
		return
	}
	ref := r.PostForm.Get("REF")
	p.mu.Lock()
	live := p.sessions[id]
	if live == nil || live.busy || live.intent == "" || !time.Now().Before(live.intentExpires) {
		p.mu.Unlock()
		p.log.Debug("reference_callback_rejected", "reason", "intent_unavailable")
		http.Error(w, "No active connection request", 409)
		return
	}
	intent := live.intent
	live.intent = "" // One attempt only, even if pickup or completion fails.
	live.intentExpires = time.Time{}
	live.busy = true
	p.mu.Unlock()
	p.log.Debug("reference_callback_accepted")
	go p.completeConnection(id, s.token, intent, ref)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func referenceFormFailure(form url.Values, expectedTargetResource string) string {
	refs := form["REF"]
	switch {
	case len(refs) == 0:
		return "reference_missing"
	case len(refs) != 1:
		return "reference_duplicate"
	case refs[0] == "":
		return "reference_empty"
	case len(refs[0]) > 2048:
		return "reference_oversized"
	case len(form) > 2:
		return "unexpected_form_fields"
	}
	// Agentless Reference ID SP Adapter Form POST includes TargetResource
	// alongside REF. It is not a redirect instruction for the portal: accept
	// only this exact callback URL and never use the submitted value.
	if len(form) == 2 {
		targets, ok := form["TargetResource"]
		if !ok {
			return "unexpected_form_fields"
		}
		if len(targets) != 1 || targets[0] != expectedTargetResource {
			return "target_resource_mismatch"
		}
	}
	return ""
}

func (p *portal) completeConnection(id, token, intent, ref string) {
	p.log.Debug("reference_completion_started")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out struct {
		ConnectionID string `json:"connection_id"`
	}
	body, _ := json.Marshal(map[string]string{"reference": ref})
	err := p.broker(ctx, token, http.MethodPost, "/v1/link-intents/"+intent+"/complete", body, &out)
	outcome := "success"
	if err != nil {
		outcome = "broker_error"
	} else if out.ConnectionID == "" {
		outcome = "missing_connection_id"
	}
	p.log.Debug("reference_completion_finished", "outcome", outcome)
	p.mu.Lock()
	if live := p.sessions[id]; live != nil {
		if err != nil || out.ConnectionID == "" {
			live.connectFailed = true
		} else {
			live.connectionID = out.ConnectionID
		}
		live.busy = false
	}
	p.mu.Unlock()
}

func (p *portal) broker(ctx context.Context, token, method, path string, body []byte, dst any) error {
	operation := "begin_link"
	if path == "/v1/connections/saml" {
		operation = "saml_exchange"
	} else if strings.HasSuffix(path, "/complete") {
		operation = "complete_link"
	}
	u := *p.c.brokerURL
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		p.log.Debug("reference_broker_call", "operation", operation, "outcome", "request_error")
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		// Transport errors can contain URLs and credentials; never log err.
		p.log.Debug("reference_broker_call", "operation", operation, "outcome", "transport_error")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		p.log.Debug("reference_broker_call", "operation", operation, "outcome", "http_error", "status", resp.StatusCode)
		return errors.New("broker rejected request")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(dst); err != nil {
		p.log.Debug("reference_broker_call", "operation", operation, "outcome", "decode_error")
		return err
	}
	p.log.Debug("reference_broker_call", "operation", operation, "outcome", "success")
	return nil
}

func (p *portal) logout(w http.ResponseWriter, r *http.Request) {
	id, s := p.current(r)
	if s == nil {
		http.Error(w, "Sign in first", 401)
		return
	}
	if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin(p.c.publicURL) {
		http.Error(w, "Invalid origin", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !same(r.PostForm.Get("csrf"), s.csrf) {
		http.Error(w, "Invalid form", 403)
		return
	}
	p.mu.Lock()
	delete(p.sessions, id)
	p.mu.Unlock()
	cookie(w, sessionCookie, "", -1, http.SameSiteNoneMode)
	// The portal session is already gone even if the browser cannot complete
	// the federated logout. Use the public PF origin so its session cookie is sent.
	logoutURL := *p.c.pfBrowserURL
	logoutURL.Path = "/idp/init_logout.openid"
	logoutURL.RawQuery = url.Values{
		"client_id":                {p.c.clientID},
		"post_logout_redirect_uri": {origin(p.c.publicURL) + "/"},
	}.Encode()
	// A separate document navigates to PF so CSP form-action 'self' cannot
	// block the cross-origin redirect after the portal form POST.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = logoutHTML.Execute(w, logoutURL.String())
}
