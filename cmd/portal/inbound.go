package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (p *portal) beginInbound(w http.ResponseWriter, r *http.Request) {
	id, s := p.current(r)
	if s == nil {
		http.Error(w, "Sign in first", 401)
		return
	}
	if !p.c.inboundEnabled || s.subject != p.c.inboundSubject {
		http.Error(w, "Exchange unavailable for this account", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.Header.Get("Origin") != origin(p.c.publicURL) || r.ParseForm() != nil || !same(r.PostForm.Get("csrf"), s.csrf) {
		http.Error(w, "Invalid form", 403)
		return
	}
	p.mu.Lock()
	live := p.sessions[id]
	if live == nil || (live.inboundState != "" && time.Now().Before(live.inboundExpires)) {
		p.mu.Unlock()
		http.Error(w, "Exchange already in progress", 409)
		return
	}
	live.inboundState, live.inboundVerifier = random(), random()
	live.inboundExpires = time.Now().Add(5 * time.Minute)
	live.inboundResult = nil
	p.mu.Unlock()
	// Complete the same-origin form navigation first: CSP form-action 'self'
	// must not be loosened for a cross-origin Microsoft redirect.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<meta http-equiv="refresh" content="0;url=/exchange/entra/continue"><a href="/exchange/entra/continue">Continue to Microsoft</a>`))
}
func (p *portal) continueInbound(w http.ResponseWriter, r *http.Request) {
	_, s := p.current(r)
	if s == nil || !p.c.inboundEnabled || s.subject != p.c.inboundSubject || s.inboundState == "" || !time.Now().Before(s.inboundExpires) {
		http.Error(w, "Exchange session missing", 403)
		return
	}
	digest := sha256.Sum256([]byte(s.inboundVerifier))
	q := url.Values{"client_id": {p.c.inboundClient}, "response_type": {"code"}, "redirect_uri": {origin(p.c.publicURL) + "/auth/entra/callback"}, "response_mode": {"query"}, "scope": {"api://e83c2af3-43d1-4f62-8bff-e619c29b5026/access_as_user"}, "state": {s.inboundState}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "prompt": {"select_account"}}
	http.Redirect(w, r, "https://login.microsoftonline.com/"+p.c.inboundTenant+"/oauth2/v2.0/authorize?"+q.Encode(), 302)
}
func (p *portal) inboundCallback(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("portal_entra_first"); err == nil && c.Value != "" {
		p.inboundFirstCallback(w, r, c.Value)
		return
	}
	id, s := p.current(r)
	if s == nil || !p.c.inboundEnabled || s.subject != p.c.inboundSubject {
		http.Error(w, "Exchange session missing", 403)
		return
	}
	q := r.URL.Query()
	p.mu.Lock()
	live := p.sessions[id]
	if live == nil || len(q["state"]) != 1 || !same(q.Get("state"), live.inboundState) || !time.Now().Before(live.inboundExpires) {
		p.mu.Unlock()
		http.Error(w, "Invalid exchange state", 403)
		return
	}
	verifier := live.inboundVerifier
	live.inboundState, live.inboundVerifier = "", "" // consume before network calls
	p.mu.Unlock()
	if q.Get("error") != "" || len(q["code"]) != 1 || q.Get("code") == "" {
		http.Error(w, "Microsoft sign-in failed; restart the exchange", 400)
		return
	}
	var result map[string]any
	body, _ := json.Marshal(map[string]string{"code": q.Get("code"), "verifier": verifier})
	if e := p.broker(r.Context(), s.token, "POST", "/v1/token-exchanges/entra", body, &result); e != nil {
		http.Error(w, "Entra to PingFederate exchange failed", 502)
		return
	}
	p.mu.Lock()
	if live := p.sessions[id]; live != nil {
		live.inboundResult = result
	}
	p.mu.Unlock()
	http.Redirect(w, r, "/#token-exchange", 303)
}

// A separate transaction cookie prevents Microsoft login from depending on a
// PF session. It grants no broker authority and cannot be used for Graph reads.
func (p *portal) beginInboundFirst(w http.ResponseWriter, r *http.Request) {
	if !p.c.inboundFirstEnabled {
		http.Error(w, "Entra-first exchange is not configured", 503)
		return
	}
	key, state, verifier := random(), random(), random()
	p.mu.Lock()
	p.pruneLocked()
	if old, err := r.Cookie("portal_inspection"); err == nil {
		delete(p.inspectionResults, old.Value)
	}
	if len(p.inboundLogins) >= 1024 {
		p.mu.Unlock()
		http.Error(w, "Too many sign-in attempts", 429)
		return
	}
	p.inboundLogins[key] = loginAttempt{state: state, verifier: verifier, expires: time.Now().Add(5 * time.Minute)}
	p.mu.Unlock()
	cookie(w, "portal_entra_first", key, 300, http.SameSiteLaxMode)
	cookie(w, "portal_inspection", "", -1, http.SameSiteStrictMode)
	digest := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {p.c.inboundClient}, "response_type": {"code"}, "redirect_uri": {origin(p.c.publicURL) + "/auth/entra/callback"}, "response_mode": {"query"}, "scope": {"api://e83c2af3-43d1-4f62-8bff-e619c29b5026/access_as_user"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "prompt": {"select_account"}}
	http.Redirect(w, r, "https://login.microsoftonline.com/"+p.c.inboundTenant+"/oauth2/v2.0/authorize?"+q.Encode(), 302)
}

func (p *portal) inboundFirstCallback(w http.ResponseWriter, r *http.Request, key string) {
	p.mu.Lock()
	a, ok := p.inboundLogins[key]
	delete(p.inboundLogins, key) // consume before all upstream calls
	p.mu.Unlock()
	cookie(w, "portal_entra_first", "", -1, http.SameSiteLaxMode)
	q := r.URL.Query()
	if !p.c.inboundFirstEnabled || !ok || !time.Now().Before(a.expires) || len(q["state"]) != 1 || !same(a.state, q.Get("state")) {
		http.Error(w, "Invalid exchange state; restart Microsoft sign-in", 403)
		return
	}
	if q.Get("error") != "" || len(q["code"]) != 1 || q.Get("code") == "" {
		http.Error(w, "Microsoft sign-in failed", 400)
		return
	}
	body, _ := json.Marshal(map[string]string{"code": q.Get("code"), "verifier": a.verifier})
	req, err := http.NewRequestWithContext(r.Context(), "POST", origin(p.c.brokerURL)+"/v1/token-exchanges/entra-first", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Exchange unavailable", 502)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("portal-inbound", p.c.inboundWorkloadSecret)
	res, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "Entra to PingFederate exchange failed", 502)
		return
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusForbidden {
		http.Error(w, "Microsoft token did not match the configured tenant, account or API permissions. Restart Microsoft sign-in with nirving@ping.darkedges.com. Broker diagnostics identify the failed check.", http.StatusForbidden)
		return
	}
	var result map[string]any
	if res.StatusCode != 200 || json.NewDecoder(http.MaxBytesReader(w, res.Body, 256<<10)).Decode(&result) != nil {
		http.Error(w, "Entra to PingFederate exchange failed", 502)
		return
	}
	if !p.c.devTokenInspection {
		delete(result, "entraToken")
		delete(result, "pfToken")
		delete(result, "pfIdToken")
	}
	p.mu.Lock()
	p.pruneLocked()
	if p.inspectionResults == nil {
		p.inspectionResults = make(map[string]inspectionResult)
	}
	if len(p.inspectionResults) >= 1024 {
		p.mu.Unlock()
		http.Error(w, "Too many inspection results", 429)
		return
	}
	resultKey := random()
	p.inspectionResults[resultKey] = inspectionResult{value: result, expires: time.Now().Add(5 * time.Minute)}
	p.mu.Unlock()
	cookie(w, "portal_inspection", resultKey, 300, http.SameSiteStrictMode)
	http.Redirect(w, r, "/#entra-first", http.StatusSeeOther)
}

type inspectionResult struct {
	value   map[string]any
	expires time.Time
}

func (p *portal) inspectionResult(w http.ResponseWriter, r *http.Request) {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		http.Error(w, "Invalid origin", 403)
		return
	}
	c, err := r.Cookie("portal_inspection")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked()
	result, ok := p.inspectionResults[c.Value]
	if !ok || !p.c.inboundFirstEnabled {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result.value)
}
