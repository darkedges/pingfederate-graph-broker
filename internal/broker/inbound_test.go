package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInboundExchange(t *testing.T) {
	for _, tc := range []struct {
		name, oid, scope, outputSubject string
		want                            int
		first                           bool
	}{
		{"success", testObject, "access_as_user", "owner", 200, false},
		{"wrong Microsoft account", testGroup, "access_as_user", "owner", 403, false},
		{"unexpected permission", testObject, "access_as_user write", "owner", 403, false},
		{"wrong PF output subject", testObject, "access_as_user", "other", 502, false},
		{"Entra first without actor", testObject, "access_as_user", "owner", 200, true},
		{"Entra first wrong account", testGroup, "access_as_user", "owner", 403, true},
		{"Entra first unexpected permission", testObject, "access_as_user write", "owner", 403, true},
		{"Entra first wrong PF subject", testObject, "access_as_user", "other", 502, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			var msToken string
			exchangeCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				switch r.URL.Path {
				case "/introspect":
					subject, client := "owner", "portal"
					if r.Form.Get("token") == "secret-pf-output" {
						subject, client = tc.outputSubject, "exchange"
						if tc.first {
							client = "first-exchange"
						}
					}
					writeJSON(w, 200, Principal{Active: true, Subject: subject, ClientID: client, Issuer: "https://pf.test", Audience: stringList{"broker"}, Expires: time.Now().Add(time.Hour).Unix(), Scope: "broker.connect", TokenType: "Bearer", Kind: "user"})
				case "/token":
					if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") != strings.Repeat("v", 43) || r.Form.Get("redirect_uri") != "https://portal.test/auth/entra/callback" {
						t.Error("incorrect code redemption")
					}
					payload, _ := json.Marshal(map[string]any{"tid": testTenant, "oid": tc.oid, "aud": "e83c2af3-43d1-4f62-8bff-e619c29b5026", "exp": time.Now().Add(time.Hour).Unix(), "scp": tc.scope})
					msToken = "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
					writeJSON(w, 200, TokenResponse{AccessToken: msToken, TokenType: "Bearer", ExpiresIn: 3600})
				case "/as/token.oauth2":
					exchangeCalls++
					if tc.first {
						if r.Form.Has("actor_token") || r.Form.Has("actor_token_type") || r.Form.Get("client_id") != "first-exchange" {
							t.Error("Entra first must use dedicated client without actor")
						}
					} else if r.Form.Get("actor_token") != "secret-actor" || r.Form.Get("actor_token_type") != accessTokenType {
						t.Error("actor contract changed")
					}
					if r.Form.Get("subject_token") != msToken || r.Form.Get("subject_token_type") != accessTokenType+":msft" {
						t.Error("incorrect exchange inputs")
					}
					writeJSON(w, 200, TokenResponse{AccessToken: "secret-pf-output", TokenType: "Bearer", IssuedTokenType: accessTokenType, ExpiresIn: 3600})
				default:
					t.Error("unexpected upstream call")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			cfg := Config{TenantID: testTenant, PFIntrospectionURL: server.URL + "/introspect", EntraTokenURL: server.URL + "/token", PFIssuer: "https://pf.test", Audience: "broker", PortalClients: []string{"portal"}, Inbound: InboundConfig{Enabled: true, ClientID: testClient, ClientSecret: "secret-client", RedirectURI: "https://portal.test/auth/entra/callback", PFClientID: "exchange", PFClientSecret: "secret-exchange", Subject: "owner", ObjectID: testObject}}
			b := New(cfg, nil, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
			b.cfg.Inbound.FirstEnabled = tc.first
			b.cfg.Inbound.WorkloadSecret = strings.Repeat("w", 32)
			b.cfg.Inbound.FirstPFClientID = "first-exchange"
			b.cfg.Inbound.FirstPFClientSecret = "secret-first-exchange"
			body, _ := json.Marshal(map[string]string{"code": "secret-code", "verifier": strings.Repeat("v", 43)})
			r := httptest.NewRequest("POST", "/v1/token-exchanges/entra", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer secret-actor")
			if tc.first {
				r.URL.Path = "/v1/token-exchanges/entra-first"
				r.SetBasicAuth("portal-inbound", strings.Repeat("w", 32))
			}
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			b.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if tc.want == 200 && (!strings.Contains(w.Body.String(), `"entraClaims"`) || !strings.Contains(w.Body.String(), `"pfClaims"`) || !strings.Contains(w.Body.String(), `"entraFingerprint"`)) {
				t.Fatal("missing safe token inspection data")
			}
			if tc.want == 403 && exchangeCalls != 0 {
				t.Fatal("mismatched Microsoft identity reached PF")
			}
			if tc.want == 403 {
				if !strings.Contains(logs.String(), `"msg":"inbound_exchange_validation"`) || !strings.Contains(logs.String(), `"tenant_ok":true`) {
					t.Fatal("missing safe identity diagnostics")
				}
				if tc.oid != testObject && !strings.Contains(logs.String(), `"user_ok":false`) {
					t.Fatal("missing user mismatch diagnostic")
				}
				if tc.scope != "access_as_user" && !strings.Contains(logs.String(), `"scope_ok":false`) {
					t.Fatal("missing scope mismatch diagnostic")
				}
			}
			for _, secret := range []string{"secret-actor", "secret-code", "secret-pf-output", "secret-client", msToken} {
				if secret != "" && (strings.Contains(w.Body.String(), secret) || strings.Contains(logs.String(), secret)) {
					t.Fatal("token or credential leaked")
				}
			}
		})
	}
}

func TestInboundDisabledAndWrongActor(t *testing.T) {
	b := New(Config{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	if e := b.inboundExchange(w, r, Principal{}); e == nil {
		t.Fatal("disabled flow accepted")
	}
	b.cfg.Inbound = InboundConfig{Enabled: true, Subject: "owner"}
	if e := b.inboundExchange(w, r, Principal{Subject: "other"}); e == nil {
		t.Fatal("wrong actor accepted")
	}
}

func TestInboundFirstRequiresWorkloadCredential(t *testing.T) {
	b := New(Config{Inbound: InboundConfig{FirstEnabled: true, WorkloadSecret: strings.Repeat("w", 32)}}, nil, nil)
	for _, credential := range []string{"", "wrong", strings.Repeat("w", 32)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/token-exchanges/entra-first", strings.NewReader(`{}`))
		if credential != "" {
			r.SetBasicAuth("portal-inbound", credential)
		}
		if credential == strings.Repeat("w", 32) {
			b.cfg.Inbound.FirstEnabled = false
		}
		b.Handler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("disabled flow or unauthorized workload accepted")
		}
	}
}

func TestInboundFirstEndpointValidation(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		valid    bool
	}{
		{"https://public.pf.test/as/token.oauth2", true},
		{"https://other.test/as/token.oauth2", false},
		{"http://public.pf.test/as/token.oauth2", false},
		{"https://user:secret@public.pf.test/as/token.oauth2", false},
		{"https://public.pf.test/as/token.oauth2?issuer=other", false},
		{"https://public.pf.test/other", false},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			c := InboundConfig{FirstEnabled: true, FirstIssuer: "https://public.pf.test", FirstTokenURL: tc.endpoint, WorkloadSecret: strings.Repeat("w", 32), FirstPFClientID: "first", FirstPFClientSecret: "fake-secret", ClientID: testClient, ClientSecret: "fake-entra", RedirectURI: "https://portal.test/auth/entra/callback", ObjectID: testObject, Subject: "owner"}
			if (c.validate(Config{TenantID: testTenant}) == nil) != tc.valid {
				t.Fatal("endpoint validation mismatch")
			}
		})
	}
}

func TestDevelopmentInspection(t *testing.T) {
	jwt := func(claims map[string]any) string {
		raw, _ := json.Marshal(claims)
		return "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
	}
	expires := time.Now().Add(time.Minute).Unix()
	ms := jwt(map[string]any{"tid": testTenant, "oid": testObject, "aud": "e83c2af3-43d1-4f62-8bff-e619c29b5026", "exp": expires, "scp": "access_as_user", "custom": "full-claims"})
	pf := jwt(map[string]any{"sub": "owner", "iss": "https://public.pf.test", "exp": expires})
	for _, tc := range []struct {
		name, idSubject, idAudience, scope string
		opaque, missing                    bool
		want                               int
	}{
		{"success", "owner", "first", "openid broker.connect", false, false, 200},
		{"wrong ID subject", "other", "first", "broker.connect openid", false, false, 502},
		{"wrong ID audience", "owner", "other", "broker.connect openid", false, false, 502},
		{"scope escalation", "owner", "first", "broker.connect openid write", false, false, 502},
		{"opaque access token", "owner", "first", "broker.connect openid", true, false, 502},
		{"missing ID token", "owner", "first", "broker.connect openid", false, true, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := jwt(map[string]any{"sub": tc.idSubject, "aud": tc.idAudience, "iss": "https://public.pf.test", "exp": expires})
			access := pf
			if tc.opaque {
				access = "opaque"
			}
			if tc.missing {
				id = ""
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				switch r.URL.Path {
				case "/token":
					writeJSON(w, 200, TokenResponse{AccessToken: ms, TokenType: "Bearer", ExpiresIn: 60})
				case "/virtual-token":
					if r.Form.Get("scope") != "broker.connect openid" || r.Form.Has("actor_token") {
						t.Error("incorrect inspection request")
					}
					writeJSON(w, 200, TokenResponse{AccessToken: access, IDToken: id, RefreshToken: "never-disclose", TokenType: "Bearer", IssuedTokenType: accessTokenType, ExpiresIn: 60})
				case "/introspect":
					writeJSON(w, 200, Principal{Active: true, Subject: "owner", ClientID: "first", Issuer: "https://public.pf.test", Audience: stringList{"broker"}, Expires: expires, Scope: tc.scope, TokenType: "Bearer", Kind: "user"})
				default:
					t.Error("unexpected endpoint")
				}
			}))
			defer server.Close()
			var logs bytes.Buffer
			b := New(Config{TenantID: testTenant, EntraTokenURL: server.URL + "/token", PFIntrospectionURL: server.URL + "/introspect", PFIssuer: "https://internal.pf.test", Audience: "broker", Inbound: InboundConfig{FirstEnabled: true, DevInspect: true, FirstIssuer: "https://public.pf.test", FirstPFClientID: "first", FirstPFClientSecret: "client-secret", ClientID: testClient, ClientSecret: "entra-secret", RedirectURI: "https://portal.test/auth/entra/callback", Subject: "owner", ObjectID: testObject}}, nil, slog.New(slog.NewJSONHandler(&logs, nil)))
			b.cfg.Inbound.FirstTokenURL = server.URL + "/virtual-token" // local mock only; production validation requires matching HTTPS origins
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", strings.NewReader(`{"code":"fake","verifier":"`+strings.Repeat("v", 43)+`"}`))
			r.Header.Set("Content-Type", "application/json")
			err := b.exchangeInbound(w, r, Principal{Subject: "owner"}, true)
			if err != nil {
				writeError(w, err)
			}
			if w.Code != tc.want {
				t.Fatalf("status %d want %d", w.Code, tc.want)
			}
			if tc.want == 200 {
				var result map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &result)
				if result["entraToken"] != ms || result["pfToken"] != pf || result["pfIdToken"] != id || result["entraClaims"].(map[string]any)["custom"] != "full-claims" {
					t.Fatal("incomplete inspection")
				}
			}
			if strings.Contains(w.Body.String(), "never-disclose") || strings.Contains(logs.String(), ms) || strings.Contains(logs.String(), pf) {
				t.Fatal("secret leaked")
			}
		})
	}
}
