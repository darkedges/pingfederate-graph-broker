package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"
)

//go:embed all:ui
var portalUI embed.FS

func (p *portal) assets() http.Handler {
	root, err := fs.Sub(portalUI, "ui")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(root))
}

func (p *portal) app(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page, err := portalUI.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "Portal UI unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce := random()
	page = bytes.ReplaceAll(page, []byte("<script "), []byte(`<script nonce="`+nonce+`" `))
	page = bytes.ReplaceAll(page, []byte("<script>"), []byte(`<script nonce="`+nonce+`">`))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

func (p *portal) apiSession(w http.ResponseWriter, r *http.Request) {
	_, s := p.current(r)
	d := struct {
		SignedIn               bool      `json:"signedIn"`
		CSRF                   string    `json:"csrf,omitempty"`
		CanConnect             bool      `json:"canConnect"`
		CanSAMLConnect         bool      `json:"canSamlConnect"`
		CanDelegate            bool      `json:"canDelegate"`
		Busy                   bool      `json:"busy"`
		Pending                bool      `json:"pending"`
		ConnectFailed          bool      `json:"connectFailed"`
		ConnectionID           string    `json:"connectionId,omitempty"`
		DelegationActive       bool      `json:"delegationActive"`
		DelegationConnectionID string    `json:"delegationConnectionId,omitempty"`
		DelegationExpires      time.Time `json:"delegationExpires,omitempty"`
		DelegationOps          []string  `json:"delegationOps,omitempty"`
	}{CanDelegate: p.c.agentClientID != "" && p.c.agentClientSecret != ""}
	if s != nil {
		d.SignedIn = true
		d.CanConnect = p.c.startURL != nil && p.c.referenceSubject != "" && s.subject == p.c.referenceSubject
		d.CanSAMLConnect = p.c.samlConnectEnabled && p.c.samlSubject != "" && s.subject == p.c.samlSubject
		d.CSRF = s.csrf
		d.Busy = s.busy
		d.Pending = s.intent != ""
		d.ConnectFailed = s.connectFailed
		d.ConnectionID = s.connectionID
		d.DelegationActive = s.delegationID != ""
		d.DelegationConnectionID = s.delegationConnectionID
		d.DelegationExpires = s.delegationExpires
		d.DelegationOps = s.delegationOps
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d)
}

func (p *portal) apiConnections(w http.ResponseWriter, r *http.Request) {
	_, s := p.current(r)
	if s == nil {
		http.Error(w, "Sign in first", http.StatusUnauthorized)
		return
	}
	out, err := p.loadConnections(r.Context(), s.token)
	if err != nil {
		http.Error(w, "Could not load connections", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
