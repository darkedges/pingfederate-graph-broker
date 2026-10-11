package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestInboundPortalStateAndPKCE(t *testing.T) {
	public, _ := url.Parse("https://portal.test")
	p := newPortal(config{publicURL: public, inboundEnabled: true, inboundSubject: "owner", inboundTenant: "tenant", inboundClient: "client"}, nil)
	p.sessions["session"] = &session{subject: "owner", csrf: "csrf", expires: time.Now().Add(time.Hour)}
	for _, origin := range []string{"https://evil.test", "https://portal.test"} {
		r := httptest.NewRequest("POST", "/exchange/entra", strings.NewReader("csrf=csrf"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session"})
		w := httptest.NewRecorder()
		p.beginInbound(w, r)
		if origin != "https://portal.test" {
			if w.Code != 403 {
				t.Fatal("CSRF origin accepted")
			}
			continue
		}
		if w.Code != 200 || !strings.Contains(w.Body.String(), "/exchange/entra/continue") {
			t.Fatal("missing same-origin transition")
		}
	}
	r := httptest.NewRequest("GET", "/exchange/entra/continue", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session"})
	w := httptest.NewRecorder()
	p.continueInbound(w, r)
	target, _ := url.Parse(w.Header().Get("Location"))
	q := target.Query()
	if target.Host != "login.microsoftonline.com" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("state") == "" || q.Get("redirect_uri") != "https://portal.test/auth/entra/callback" {
		t.Fatal("invalid authorization redirect")
	}
	for _, state := range []string{"wrong", q.Get("state")} {
		r := httptest.NewRequest("GET", "/auth/entra/callback?error=access_denied&state="+state, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session"})
		w := httptest.NewRecorder()
		p.inboundCallback(w, r)
		want := 403
		if state == q.Get("state") {
			want = 400
		}
		if w.Code != want {
			t.Fatalf("callback %d want %d", w.Code, want)
		}
	}
	if p.sessions["session"].inboundState != "" {
		t.Fatal("state was not consumed")
	}
}
