package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEntraFirstWithoutPFSession(t *testing.T) {
	public, _ := url.Parse("https://portal.test")
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		user, secret, ok := r.BasicAuth()
		if !ok || user != "portal-inbound" || secret != strings.Repeat("w", 32) || r.URL.Path != "/v1/token-exchanges/entra-first" {
			t.Error("workload authentication missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subject":"owner","identityTokenStatus":"Not requested"}`))
	}))
	defer backend.Close()
	brokerURL, _ := url.Parse(backend.URL)
	p := newPortal(config{publicURL: public, brokerURL: brokerURL, inboundFirstEnabled: true, inboundTenant: "tenant", inboundClient: "client", inboundWorkloadSecret: strings.Repeat("w", 32)}, nil)
	w := httptest.NewRecorder()
	p.handler().ServeHTTP(w, httptest.NewRequest("GET", "/exchange/entra-first", nil))
	if w.Code != 302 {
		t.Fatal("Microsoft redirect missing")
	}
	target, _ := url.Parse(w.Header().Get("Location"))
	if target.Host != "login.microsoftonline.com" || target.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("incorrect Microsoft PKCE redirect")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 2 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe transaction cookie")
	}
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/auth/entra/callback?code=fake&state="+target.Query().Get("state"), nil)
		r.AddCookie(cookies[0])
		w = httptest.NewRecorder()
		p.handler().ServeHTTP(w, r)
		if i == 0 && (w.Code != 303 || w.Header().Get("Location") != "/#entra-first") {
			t.Fatal("exchange did not return to portal without PF session")
		}
		if i == 1 && w.Code != 403 {
			t.Fatal("callback replay accepted")
		}
	}
	if calls != 1 || len(p.sessions) != 0 {
		t.Fatal("unexpected authority or repeated redemption")
	}
}

func TestInspectionResultBrowserBinding(t *testing.T) {
	public, _ := url.Parse("https://portal.test")
	p := newPortal(config{publicURL: public, inboundFirstEnabled: true}, nil)
	p.inspectionResults = map[string]inspectionResult{"key": {value: map[string]any{"pfToken": "fake-token"}, expires: time.Now().Add(time.Minute)}, "expired": {value: map[string]any{"pfToken": "fake-token"}, expires: time.Now().Add(-time.Minute)}}
	for _, tc := range []struct {
		key, site string
		want      int
	}{{"", "", 404}, {"other", "", 404}, {"expired", "", 404}, {"key", "cross-site", 403}, {"key", "same-origin", 200}} {
		r := httptest.NewRequest("GET", "/api/exchange/result", nil)
		if tc.key != "" {
			r.AddCookie(&http.Cookie{Name: "portal_inspection", Value: tc.key})
		}
		r.Header.Set("Sec-Fetch-Site", tc.site)
		w := httptest.NewRecorder()
		p.handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("status %d, want %d", w.Code, tc.want)
		}
		if w.Code == 200 && (!strings.Contains(w.Body.String(), "fake-token") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store")) {
			t.Fatal("missing result or no-store")
		}
	}
}

func TestInspectionPortalOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"developmentInspection":true,"entraToken":"fake-entra","pfToken":"fake-pf","pfIdToken":"fake-id"}`))
			}))
			defer upstream.Close()
			public, _ := url.Parse("https://portal.test")
			backend, _ := url.Parse(upstream.URL)
			p := newPortal(config{publicURL: public, brokerURL: backend, inboundFirstEnabled: true, devTokenInspection: enabled}, nil)
			p.inboundLogins["login"] = loginAttempt{state: "state", verifier: "verifier", expires: time.Now().Add(time.Minute)}
			r := httptest.NewRequest("GET", "/auth/entra/callback?code=fake&state=state", nil)
			r.AddCookie(&http.Cookie{Name: "portal_entra_first", Value: "login"})
			w := httptest.NewRecorder()
			p.handler().ServeHTTP(w, r)
			if w.Code != 303 {
				t.Fatal("callback failed")
			}
			var resultCookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "portal_inspection" {
					resultCookie = c
				}
			}
			if resultCookie == nil || !resultCookie.Secure || !resultCookie.HttpOnly || resultCookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("unsafe result cookie")
			}
			r = httptest.NewRequest("GET", "/api/exchange/result", nil)
			r.AddCookie(resultCookie)
			w = httptest.NewRecorder()
			p.handler().ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal("result unavailable")
			}
			for _, token := range []string{"fake-entra", "fake-pf", "fake-id"} {
				if strings.Contains(w.Body.String(), token) != enabled {
					t.Fatal("portal inspection opt-in not enforced")
				}
			}
		})
	}
}

func TestEntraFirstRejectsInvalidTransactions(t *testing.T) {
	public, _ := url.Parse("https://portal.test")
	for _, tc := range []struct {
		name, state string
		expires     time.Time
	}{
		{"wrong state", "wrong", time.Now().Add(time.Minute)},
		{"expired", "state", time.Now().Add(-time.Minute)},
		{"duplicate state", "state&state=state", time.Now().Add(time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPortal(config{publicURL: public, inboundFirstEnabled: true}, nil)
			p.inboundLogins["key"] = loginAttempt{state: "state", verifier: "verifier", expires: tc.expires}
			r := httptest.NewRequest("GET", "/auth/entra/callback?code=fake&state="+tc.state, nil)
			r.AddCookie(&http.Cookie{Name: "portal_entra_first", Value: "key"})
			w := httptest.NewRecorder()
			p.handler().ServeHTTP(w, r)
			if w.Code != 403 || len(p.inboundLogins) != 0 {
				t.Fatal("invalid transaction accepted or not consumed")
			}
		})
	}
}
