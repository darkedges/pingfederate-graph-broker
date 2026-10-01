package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNextAppShellAndSessionRedaction(t *testing.T) {
	p := newPortal(config{}, nil)
	p.sessions["session-1"] = &session{token: "private-pf-access-token", csrf: "csrf-value", intent: "private-reference-intent", intentExpires: time.Now().Add(time.Minute), expires: time.Now().Add(time.Hour), connectionID: "connection-1", delegationID: "delegation-1", delegationConnectionID: "connection-1", delegationExpires: time.Now().Add(time.Hour), delegationOps: []string{"directory.find_users"}}
	server := httptest.NewServer(p.handler())
	defer server.Close()
	request := func(path string, authenticated bool) (int, string, http.Header) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-1"})
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body), resp.Header
	}
	status, shell, headers := request("/", true)
	if status != http.StatusOK || !strings.Contains(shell, "Broker Portal") || !strings.Contains(shell, "/_next/static/") {
		t.Fatal("Next.js static app shell was not served")
	}
	if strings.Contains(shell, "private-pf-access-token") || strings.Contains(shell, "private-reference-intent") {
		t.Fatal("app shell leaked server-side auth material")
	}
	scripts := regexp.MustCompile(`<script\b[^>]*>`).FindAllString(shell, -1)
	if len(scripts) == 0 {
		t.Fatal("built app shell has no scripts")
	}
	for _, script := range scripts {
		if !strings.Contains(script, `nonce="`) {
			t.Fatal("script tag is missing a CSP nonce")
		}
	}
	if !strings.Contains(headers.Get("Content-Security-Policy"), "script-src 'self' 'nonce-") || !strings.Contains(headers.Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatal("app shell CSP is missing script nonce or form restriction")
	}
	asset := regexp.MustCompile(`/_next/static/[^" ]+\.js`).FindString(shell)
	if asset == "" {
		t.Fatal("app shell is missing a JavaScript asset")
	}
	status, _, _ = request(asset, false)
	if status != http.StatusOK {
		t.Fatalf("Next.js asset status %d", status)
	}
	status, state, headers := request("/api/session", true)
	if status != http.StatusOK || !strings.Contains(state, `"signedIn":true`) || !strings.Contains(state, `"csrf":"csrf-value"`) || !strings.Contains(state, `"delegationActive":true`) || !strings.Contains(state, `"delegationConnectionId":"connection-1"`) || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("session API did not return safe state")
	}
	for _, secret := range []string{"private-pf-access-token", "private-reference-intent", "delegation-1"} {
		if strings.Contains(state, secret) {
			t.Fatal("session API leaked a server-side value")
		}
	}
	status, state, _ = request("/api/session", false)
	if status != http.StatusOK || !strings.Contains(state, `"signedIn":false`) || strings.Contains(state, "csrf-value") {
		t.Fatal("anonymous session API leaked signed-in state")
	}
}
