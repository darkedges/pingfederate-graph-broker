package broker

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

const GraphScopes = "https://graph.microsoft.com/User.ReadBasic.All https://graph.microsoft.com/GroupMember.Read.All"

// Entra OBO requires /.default. The returned token is still checked against
// the read-only Graph scope allowlist before it can be stored or used.
const GraphOBOScope = "https://graph.microsoft.com/.default"

var guid = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Config struct {
	Listen, DataDir                                          string
	Key                                                      []byte
	PFIntrospectionURL, PFIssuer, Audience                   string
	PFClientID, PFClientSecret                               string
	PFPickupURL, PFAdapterID, PFPickupUser, PFPickupPassword string
	PortalClients, AgentClients                              []string
	TenantID, EntraClientID, EntraClientSecret               string
	EntraTokenURL, GraphBaseURL                              string
	SAML                                                     SAMLConfig
}

// SAMLConfig is a dedicated, opt-in one-user exchange. It is deliberately
// separate from the refreshable Entra OIDC connector.
type SAMLConfig struct {
	Active                                          bool
	PFTokenURL, PFClientID, PFClientSecret          string
	TenantID, SAMLClientID, SAMLClientSecret, Scope string
	OBOClientID, OBOClientSecret                    string
	ExpectedPFSubject, ExpectedEntraOID             string
	TokenURL                                        string
}

func (c SAMLConfig) Enabled() bool { return c.Active }

func LoadConfig() (Config, error) {
	c := Config{
		Listen: env("LISTEN_ADDR", "127.0.0.1:8080"), DataDir: env("DATA_DIR", "./data"),
		PFIntrospectionURL: os.Getenv("PF_INTROSPECTION_URL"), PFIssuer: os.Getenv("PF_ISSUER"),
		Audience: os.Getenv("BROKER_AUDIENCE"), PFClientID: os.Getenv("PF_INTROSPECTION_CLIENT_ID"),
		PFClientSecret: os.Getenv("PF_INTROSPECTION_CLIENT_SECRET"),
		PFPickupURL:    os.Getenv("PF_PICKUP_URL"), PFAdapterID: os.Getenv("PF_SP_ADAPTER_ID"),
		PFPickupUser: os.Getenv("PF_PICKUP_USER"), PFPickupPassword: os.Getenv("PF_PICKUP_PASSWORD"),
		PortalClients: split(os.Getenv("PF_PORTAL_CLIENT_IDS")), AgentClients: split(os.Getenv("PF_AGENT_CLIENT_IDS")),
		TenantID: os.Getenv("ENTRA_TENANT_ID"), EntraClientID: os.Getenv("ENTRA_CLIENT_ID"),
		EntraClientSecret: os.Getenv("ENTRA_CLIENT_SECRET"), GraphBaseURL: "https://graph.microsoft.com/v1.0",
		SAML: SAMLConfig{
			Active:     os.Getenv("SAML_ENABLED") == "true",
			PFTokenURL: os.Getenv("SAML_PF_TOKEN_URL"), PFClientID: os.Getenv("SAML_PF_CLIENT_ID"), PFClientSecret: os.Getenv("SAML_PF_CLIENT_SECRET"),
			TenantID: os.Getenv("SAML_ENTRA_TENANT_ID"), SAMLClientID: os.Getenv("SAML_ENTRA_CLIENT_ID"), SAMLClientSecret: os.Getenv("SAML_ENTRA_CLIENT_SECRET"), Scope: os.Getenv("SAML_ENTRA_SCOPE"),
			OBOClientID: os.Getenv("SAML_OBO_CLIENT_ID"), OBOClientSecret: os.Getenv("SAML_OBO_CLIENT_SECRET"),
			ExpectedPFSubject: os.Getenv("SAML_EXPECTED_PF_SUBJECT"), ExpectedEntraOID: os.Getenv("SAML_EXPECTED_ENTRA_OID"),
		},
	}
	var err error
	c.Key, err = base64.StdEncoding.DecodeString(os.Getenv("TOKEN_ENCRYPTION_KEY"))
	if err != nil || len(c.Key) != 32 {
		return c, errors.New("TOKEN_ENCRYPTION_KEY must be base64 encoding of 32 random bytes")
	}
	for name, value := range map[string]string{
		"PF_ISSUER": c.PFIssuer, "BROKER_AUDIENCE": c.Audience, "PF_INTROSPECTION_CLIENT_ID": c.PFClientID,
		"PF_INTROSPECTION_CLIENT_SECRET": c.PFClientSecret, "PF_SP_ADAPTER_ID": c.PFAdapterID,
		"PF_PICKUP_USER": c.PFPickupUser, "PF_PICKUP_PASSWORD": c.PFPickupPassword,
		"ENTRA_CLIENT_SECRET": c.EntraClientSecret,
	} {
		if strings.TrimSpace(value) == "" {
			return c, fmt.Errorf("%s is required", name)
		}
	}
	if !guid.MatchString(c.TenantID) || !guid.MatchString(c.EntraClientID) {
		return c, errors.New("ENTRA_TENANT_ID and ENTRA_CLIENT_ID must be GUIDs")
	}
	if len(c.PortalClients) == 0 || len(c.AgentClients) == 0 {
		return c, errors.New("PF_PORTAL_CLIENT_IDS and PF_AGENT_CLIENT_IDS are required")
	}
	for _, id := range c.PortalClients {
		if contains(c.AgentClients, id) {
			return c, errors.New("portal and agent client allowlists must not overlap")
		}
	}
	for _, raw := range []string{c.PFIntrospectionURL, c.PFPickupURL, c.PFIssuer} {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, errors.New("PingFederate URLs must be absolute HTTPS URLs without credentials, query or fragment")
		}
	}
	c.EntraTokenURL = "https://login.microsoftonline.com/" + c.TenantID + "/oauth2/v2.0/token"
	if c.SAML.Enabled() {
		if err := c.SAML.validate(c.PFIntrospectionURL); err != nil {
			return c, err
		}
		c.SAML.TokenURL = "https://login.microsoftonline.com/" + c.SAML.TenantID + "/oauth2/v2.0/token"
	}
	return c, nil
}

func (c SAMLConfig) validate(introspectionURL string) error {
	for _, value := range []string{c.PFClientID, c.PFClientSecret, c.SAMLClientSecret, c.OBOClientSecret, c.ExpectedPFSubject, c.Scope} {
		if strings.TrimSpace(value) == "" {
			return errors.New("SAML exchange configuration is incomplete")
		}
	}
	if !guid.MatchString(c.TenantID) || !guid.MatchString(c.SAMLClientID) || !guid.MatchString(c.OBOClientID) || !guid.MatchString(c.ExpectedEntraOID) {
		return errors.New("SAML exchange GUID configuration is invalid")
	}
	pf, err := url.Parse(c.PFTokenURL)
	intro, _ := url.Parse(introspectionURL)
	if err != nil || pf.Scheme != "https" || intro == nil || pf.Host != intro.Host || pf.Path != "/as/token.oauth2" || pf.User != nil || pf.RawQuery != "" || pf.Fragment != "" {
		return errors.New("SAML PF token endpoint must use the configured PF HTTPS origin")
	}
	scopes := strings.Fields(c.Scope)
	if len(scopes) < 1 || len(scopes) > 4 {
		return errors.New("SAML scope must name one intermediate API scope")
	}
	api, err := url.Parse(scopes[0])
	if err != nil || api.Scheme != "api" || !guid.MatchString(api.Host) || api.Path != "/access_as_user" || api.RawQuery != "" || api.Fragment != "" {
		return errors.New("SAML scope must name one intermediate API access_as_user scope")
	}
	seen := map[string]bool{}
	for _, scope := range scopes[1:] {
		if (scope != "openid" && scope != "profile" && scope != "email") || seen[scope] {
			return errors.New("SAML scope contains an unsupported permission")
		}
		seen[scope] = true
	}
	return nil
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func split(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Strict allowlist: never silently import a grant with directory writes or other APIs.
func validateGraphScopes(scope string) error {
	seen := map[string]bool{}
	for _, s := range strings.Fields(scope) {
		s = strings.TrimPrefix(s, "https://graph.microsoft.com/")
		switch s {
		case "openid", "profile", "email", "offline_access", "User.Read", "User.ReadBasic.All", "GroupMember.Read.All":
			seen[s] = true
		default:
			return errors.New("unexpected upstream scope")
		}
	}
	if !seen["User.ReadBasic.All"] || !seen["GroupMember.Read.All"] {
		return errors.New("required read permissions missing")
	}
	return nil
}
