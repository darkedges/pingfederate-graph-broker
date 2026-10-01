package broker

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mockJWT(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestAADSTSErrorCodeDoesNotReturnResponseDetails(t *testing.T) {
	body := []byte(`{"error":"invalid_grant","error_description":"AADSTS65001: user@example.test assertion-secret-value"}`)
	if got := aadstsErrorCode(body); got != "65001" {
		t.Fatalf("unexpected safe error code %q", got)
	}
	if got := aadstsErrorCode([]byte(`{"error_description":"account details only"}`)); got != "" {
		t.Fatalf("unexpected error details %q", got)
	}
}

func TestGraphScopeDiagnosticsDoesNotExposeValues(t *testing.T) {
	for _, tc := range []struct {
		scope              string
		basic, group, selector, other bool
	}{
		{"User.ReadBasic.All GroupMember.Read.All", true, true, false, false},
		{"https://graph.microsoft.com/User.ReadBasic.All custom.secret.scope", true, false, false, true},
		{"openid profile", false, false, false, false},
		{GraphOBOScope + " User.ReadBasic.All GroupMember.Read.All", true, true, true, false},
	} {
		basic, group, selector, other := graphScopeDiagnostics(tc.scope)
		if basic != tc.basic || group != tc.group || selector != tc.selector || other != tc.other {
			t.Fatal("incorrect scope classification")
		}
	}
}

func TestSAMLConnectionIsBoundAndShortLived(t *testing.T) {
	for _, scenario := range []string{"ok", "default_scope", "mixed_default_scope", "default_scope_broad_claim", "wrong_pf_user", "wrong_entra_user", "broad_graph_scope"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			const subject = "owner-1"
			const apiAudience = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
			var calls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.ParseForm() != nil {
					t.Error("invalid exchange request")
					w.WriteHeader(400)
					return
				}
				calls++
				switch r.URL.Path {
				case "/pf":
					if r.PostForm.Get("subject_token") != "owner" || r.PostForm.Get("subject_token_type") != accessTokenType || r.PostForm.Get("requested_token_type") != saml11Type {
						t.Error("PF request did not use introspected portal token")
					}
					writeJSON(w, 200, map[string]any{"access_token": "assertion", "issued_token_type": saml11Type, "token_type": "N_A", "expires_in": 600})
				case "/entra":
					if r.PostForm.Get("grant_type") == saml11Grant {
						if r.PostForm.Get("assertion") != "assertion" {
							t.Error("SAML assertion missing")
						}
						object := testObject
						if scenario == "wrong_entra_user" {
							object = testGroup
						}
						token := mockJWT(map[string]any{"aud": apiAudience, "tid": testTenant, "oid": object, "scp": "access_as_user", "exp": time.Now().Add(time.Hour).Unix()})
						writeJSON(w, 200, TokenResponse{AccessToken: token, TokenType: "Bearer", Scope: "api://" + apiAudience + "/access_as_user", ExpiresIn: 3600})
					} else if r.PostForm.Get("grant_type") == oboGrant {
						if r.PostForm.Get("scope") != GraphOBOScope || r.PostForm.Get("requested_token_use") != "on_behalf_of" {
							t.Error("OBO did not request the required Graph .default scope")
						}
						scope := "User.ReadBasic.All GroupMember.Read.All"
						if scenario == "broad_graph_scope" || scenario == "default_scope_broad_claim" {
							scope += " IdentityProvider.ReadWrite.All"
						}
						token := mockJWT(map[string]any{"aud": "https://graph.microsoft.com", "tid": testTenant, "oid": testObject, "scp": scope, "exp": time.Now().Add(10 * time.Minute).Unix()})
						responseScope := scope
						if scenario == "default_scope" || scenario == "default_scope_broad_claim" {
							responseScope = GraphOBOScope
						}
						if scenario == "mixed_default_scope" {
							responseScope = GraphOBOScope + " " + scope
						}
						writeJSON(w, 200, TokenResponse{AccessToken: token, TokenType: "Bearer", Scope: responseScope, ExpiresIn: 600})
					} else {
						t.Error("unexpected Entra grant")
						w.WriteHeader(400)
					}
				default:
					t.Error("unexpected endpoint")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			f.b.cfg.SAML = SAMLConfig{Active: true, PFTokenURL: server.URL + "/pf", PFClientID: "pf-client", PFClientSecret: "pf-secret", TenantID: testTenant,
				SAMLClientID: testClient, SAMLClientSecret: "saml-secret", Scope: "api://" + apiAudience + "/access_as_user", OBOClientID: testClient,
				OBOClientSecret: "obo-secret", ExpectedPFSubject: subject, ExpectedEntraOID: testObject, TokenURL: server.URL + "/entra"}
			if scenario == "wrong_pf_user" {
				f.b.cfg.SAML.ExpectedPFSubject = "other-owner"
			}
			w := f.call("POST", "/v1/connections/saml", "owner", "")
			if scenario == "ok" || scenario == "default_scope" || scenario == "mixed_default_scope" {
				id := jsonField(t, w, 201, "connection_id")
				if id == "" || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "assertion") {
					t.Fatal("connection response leaked credentials")
				}
				var c Connection
				_ = f.s.View(func(s State) error { c = s.Connections[id]; return nil })
				if c.Mode != "saml" || c.RefreshToken != "" || c.Owner != subject || c.ObjectID != testObject {
					t.Fatal("invalid stored SAML connection")
				}
				if c.ExpiresAt.After(time.Now().Add(11 * time.Minute)) {
					t.Fatal("connection exceeded Graph token life")
				}
				body, _ := json.Marshal(map[string]any{"agent_client_id": "agent-1", "operations": []string{"directory.find_users"}, "expires_in_seconds": 3600})
				did := jsonField(t, f.call("POST", "/v1/connections/"+id+"/delegations", "owner", string(body)), 201, "delegation_id")
				if did == "" {
					t.Fatal("missing delegation")
				}
				_ = f.s.View(func(s State) error {
					if s.Delegations[did].ExpiresAt.After(c.ExpiresAt) {
						t.Error("delegation outlived SAML connection")
					}
					return nil
				})
				_ = f.s.Update(func(s *State) error {
					c := s.Connections[id]
					c.ExpiresAt = time.Now().Add(-time.Second)
					s.Connections[id] = c
					return nil
				})
				if got := f.call("GET", "/v1/delegations/"+did+"/users", "agent", "").Code; got != 409 {
					t.Fatalf("expired SAML connection status=%d", got)
				}
			} else {
				if w.Code < 400 || w.Code >= 500 && scenario == "wrong_pf_user" {
					t.Fatalf("unexpected status %d", w.Code)
				}
				_ = f.s.View(func(s State) error {
					if len(s.Connections) != 0 {
						t.Error("invalid exchange saved a connection")
					}
					return nil
				})
			}
			if scenario == "wrong_pf_user" && calls != 0 {
				t.Fatal("called upstream for wrong PF subject")
			}
		})
	}
}

func TestSAMLConfigRejectsOtherPFOrigin(t *testing.T) {
	c := SAMLConfig{PFTokenURL: "https://other.example/as/token.oauth2", PFClientID: "pf", PFClientSecret: "secret", TenantID: testTenant,
		SAMLClientID: testClient, SAMLClientSecret: "secret", Scope: "api://aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/access_as_user",
		OBOClientID: testClient, OBOClientSecret: "secret", ExpectedPFSubject: "owner-1", ExpectedEntraOID: testObject}
	if c.validate("https://pf.example/as/introspect.oauth2") == nil {
		t.Fatal("accepted a different PF host")
	}
}
