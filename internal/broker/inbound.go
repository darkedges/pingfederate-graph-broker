package broker

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const inboundScope = "api://e83c2af3-43d1-4f62-8bff-e619c29b5026/access_as_user"

type InboundConfig struct {
	DevInspect                                                                         bool
	FirstIssuer                                                                        string
	FirstTokenURL                                                                      string
	TenantID                                                                           string
	FirstEnabled                                                                       bool
	WorkloadSecret, FirstPFClientID, FirstPFClientSecret                               string
	Enabled                                                                            bool
	ClientID, ClientSecret, RedirectURI, PFClientID, PFClientSecret, Subject, ObjectID string
}

func loadInboundConfig() InboundConfig {
	return InboundConfig{FirstEnabled: os.Getenv("INBOUND_FIRST_ENABLED") == "true", WorkloadSecret: os.Getenv("INBOUND_WORKLOAD_SECRET"), FirstPFClientID: os.Getenv("INBOUND_FIRST_PF_CLIENT_ID"), FirstPFClientSecret: os.Getenv("INBOUND_FIRST_PF_CLIENT_SECRET"), Enabled: os.Getenv("INBOUND_ENABLED") == "true", ClientID: os.Getenv("INBOUND_ENTRA_CLIENT_ID"), ClientSecret: os.Getenv("INBOUND_ENTRA_CLIENT_SECRET"), RedirectURI: os.Getenv("INBOUND_REDIRECT_URI"), PFClientID: os.Getenv("INBOUND_PF_CLIENT_ID"), PFClientSecret: os.Getenv("INBOUND_PF_CLIENT_SECRET"), Subject: os.Getenv("INBOUND_PF_SUBJECT"), ObjectID: os.Getenv("INBOUND_ENTRA_OBJECT_ID")}
}
func (c InboundConfig) validate(b Config) error {
	if !c.Enabled && !c.FirstEnabled {
		return nil
	}
	if c.TenantID != "" && !guid.MatchString(c.TenantID) {
		return errors.New("invalid inbound Entra tenant")
	}
	if c.FirstIssuer != "" {
		issuer, err := url.Parse(c.FirstIssuer)
		if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
			return errors.New("invalid Entra-first PF issuer")
		}
	}
	if c.FirstEnabled && (len(c.WorkloadSecret) < 32 || c.FirstPFClientID == "" || len(c.FirstPFClientSecret) < 8 || c.FirstPFClientID == c.PFClientID) {
		return errors.New("Entra-first exchange requires a dedicated PF client and workload secret of at least 32 characters")
	}
	u, e := url.Parse(c.RedirectURI)
	if c.FirstTokenURL != "" {
		endpoint, err := url.Parse(c.FirstTokenURL)
		issuer, issuerErr := url.Parse(c.FirstIssuer)
		if err != nil || issuerErr != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/as/token.oauth2" || endpoint.Scheme != issuer.Scheme || endpoint.Host != issuer.Host {
			return errors.New("Entra-first token endpoint must use the configured PF HTTPS issuer origin")
		}
	}
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/auth/entra/callback" || !guid.MatchString(c.ClientID) || !guid.MatchString(c.ObjectID) || !guid.MatchString(b.TenantID) || c.ClientSecret == "" || (c.Enabled && (c.PFClientSecret == "" || c.PFClientID == "")) || c.Subject == "" {
		return errors.New("inbound exchange configuration is incomplete or invalid")
	}
	return nil
}

// Outside the explicitly enabled development inspector, Entra token bytes
// never leave the broker. PF verifies the Microsoft JWT's
// signature/issuer/audience and enforces the same immutable binding as below.
func (b *Broker) inboundExchange(w http.ResponseWriter, r *http.Request, p Principal) error {
	return b.exchangeInbound(w, r, p, false)
}

// Workload authentication authorizes code redemption, not directory access.
// This endpoint returns metadata by default. Its opt-in development inspector
// returns token bytes to the authenticated portal workload, never a user session.
func (b *Broker) inboundFirst(w http.ResponseWriter, r *http.Request) {
	c := b.cfg.Inbound
	user, secret, ok := r.BasicAuth()
	if !c.FirstEnabled || !ok || user != "portal-inbound" || len(c.WorkloadSecret) < 32 || subtle.ConstantTimeCompare([]byte(secret), []byte(c.WorkloadSecret)) != 1 {
		writeError(w, fail(401, "inbound_workload_unauthorized"))
		return
	}
	e := b.exchangeInbound(w, r, Principal{Subject: c.Subject}, true)
	if e != nil {
		writeError(w, e)
	}
	b.audit(r, Principal{}, "entra_first_exchange", e)
}

func (b *Broker) exchangeInbound(w http.ResponseWriter, r *http.Request, p Principal, first bool) error {
	c := b.cfg.Inbound
	if (!first && !c.Enabled) || (first && !c.FirstEnabled) {
		return fail(503, "inbound_exchange_not_configured")
	}
	if p.Subject != c.Subject {
		return fail(403, "inbound_subject_not_allowed")
	}
	var in struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	if e := decodeBody(w, r, &in); e != nil {
		return e
	}
	if len(in.Code) < 1 || len(in.Code) > 16384 || len(in.Verifier) < 43 || len(in.Verifier) > 128 || strings.ContainsAny(in.Verifier, " \r\n\t") {
		return fail(400, "invalid_exchange_code")
	}
	tenant, tokenURL := b.cfg.TenantID, b.cfg.EntraTokenURL
	if c.TenantID != "" {
		tenant = c.TenantID
		tokenURL = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
	}
	ms, e := b.exchangeForm(r.Context(), tokenURL, url.Values{"grant_type": {"authorization_code"}, "client_id": {c.ClientID}, "client_secret": {c.ClientSecret}, "redirect_uri": {c.RedirectURI}, "code": {in.Code}, "code_verifier": {in.Verifier}, "scope": {inboundScope}}, "inbound_entra_code")
	if e != nil {
		return e
	}
	claims, e := parseTokenClaims(ms.AccessToken)
	apiAudience := "e83c2af3-43d1-4f62-8bff-e619c29b5026"
	parsedOK := e == nil
	bearerOK := strings.EqualFold(ms.TokenType, "Bearer")
	tenantOK := claims.Tenant == tenant
	userOK := claims.Object == c.ObjectID
	expiryOK := claims.Expires > time.Now().Unix()
	audienceOK := claims.hasAudience(apiAudience) || claims.hasAudience("api://"+apiAudience)
	scopeOK := claims.Scopes == "access_as_user"
	if !parsedOK || !bearerOK || !tenantOK || !userOK || !expiryOK || !audienceOK || !scopeOK {
		// Only fixed field names and booleans: no tokens, claims, identities,
		// upstream bodies, authorization codes or callback query strings.
		b.log.Info("inbound_exchange_validation", "stage", "entra_identity", "outcome", "rejected",
			"parsed_ok", parsedOK, "bearer_ok", bearerOK, "tenant_ok", tenantOK,
			"user_ok", userOK, "expiry_ok", expiryOK, "audience_ok", audienceOK, "scope_ok", scopeOK)
		return fail(403, "inbound_identity_mismatch")
	}
	endpoint, _ := url.Parse(b.cfg.PFIntrospectionURL)
	endpoint.Path = "/as/token.oauth2"
	if first && c.FirstTokenURL != "" {
		endpoint, _ = url.Parse(c.FirstTokenURL)
	}
	form := url.Values{"grant_type": {pfExchangeGrant}, "subject_token": {ms.AccessToken}, "subject_token_type": {accessTokenType + ":msft"}, "requested_token_type": {accessTokenType}, "client_id": {c.PFClientID}, "client_secret": {c.PFClientSecret}, "scope": {"broker.connect"}}
	outputClient := c.PFClientID
	if first {
		form.Set("client_id", c.FirstPFClientID)
		form.Set("client_secret", c.FirstPFClientSecret)
		if c.DevInspect {
			form.Set("scope", "broker.connect openid")
		}
		outputClient = c.FirstPFClientID
	} else {
		form.Set("actor_token", strings.Fields(r.Header.Get("Authorization"))[1]) // introspected by b.user
		form.Set("actor_token_type", accessTokenType)
	}
	pf, e := b.exchangeForm(r.Context(), endpoint.String(), form, "inbound_pingfederate")
	if e != nil {
		return e
	}
	if pf.IssuedTokenType != accessTokenType || !strings.EqualFold(pf.TokenType, "Bearer") {
		return fail(502, "invalid_inbound_pf_token")
	}
	// Reuse every existing introspection requirement, with a dedicated exchange
	// client allowlist for this output only. Never add it to portal callers.
	outputConfig := b.cfg
	outputConfig.PortalClients = []string{outputClient}
	if first && c.FirstIssuer != "" {
		outputConfig.PFIssuer = c.FirstIssuer
	}
	copyBroker := New(outputConfig, nil, b.log)
	copyBroker.http = b.http
	check := r.Clone(r.Context())
	check.Header = r.Header.Clone()
	check.Header.Set("Authorization", "Bearer "+pf.AccessToken)
	verified, e := copyBroker.authenticate(check, "user", "broker.connect")
	expectedScope := "broker.connect"
	if first && c.DevInspect {
		expectedScope = "broker.connect openid"
	}
	if e != nil || verified.Subject != p.Subject || !exactInspectionScopes(verified.Scope, expectedScope) {
		return fail(502, "invalid_inbound_pf_token")
	}
	digest := sha256.Sum256([]byte(pf.AccessToken))
	if first && c.DevInspect {
		entraClaims, err := inspectionClaims(ms.AccessToken)
		if err != nil {
			return err
		}
		pfClaims, err := inspectionClaims(pf.AccessToken)
		if err != nil {
			return fail(502, "inspection_requires_pf_jwt")
		}
		idClaims, err := inspectionClaims(pf.IDToken)
		if err != nil {
			return fail(502, "inspection_requires_pf_id_token")
		}
		// Received directly from the trusted PF TLS token endpoint, not browser
		// input. Bind the ID token to this verified exchange; never authenticate
		// a directory request using these display-only decoded claims.
		id, err := parseTokenClaims(pf.IDToken)
		if err != nil || id.Issuer != outputConfig.PFIssuer || id.Subject != verified.Subject || !id.hasAudience(outputClient) || id.Expires <= time.Now().Unix() {
			return fail(502, "invalid_inspection_id_token")
		}
		writeJSON(w, 200, map[string]any{
			"developmentInspection": true,
			"entraToken":            ms.AccessToken, "entraClaims": entraClaims,
			"pfToken": pf.AccessToken, "pfClaims": pfClaims,
			"pfIdToken": pf.IDToken, "pfIdClaims": idClaims,
			"identityTokenStatus": "Returned by PingFederate's OpenID Connect token-exchange policy.",
		})
		return nil
	}
	entraDigest := sha256.Sum256([]byte(ms.AccessToken))
	// Explicit display allowlists, never serialize the token response or an
	// arbitrary JWT payload. The PF reference token is inspected, not JWT-decoded.
	writeJSON(w, 200, map[string]any{"issuer": verified.Issuer, "audience": verified.Audience, "subject": verified.Subject, "scope": verified.Scope, "expiresAt": time.Unix(verified.Expires, 0).UTC(), "fingerprint": hex.EncodeToString(digest[:]), "entraFingerprint": hex.EncodeToString(entraDigest[:]), "identityTokenStatus": "Not requested: access-token exchange only", "tenantId": claims.Tenant, "objectId": claims.Object,
		"entraClaims": map[string]any{"iss": claims.Issuer, "sub": claims.Subject, "aud": claims.Audience, "tid": claims.Tenant, "oid": claims.Object, "scp": claims.Scopes, "exp": claims.Expires},
		"pfClaims":    map[string]any{"active": verified.Active, "iss": verified.Issuer, "aud": verified.Audience, "sub": verified.Subject, "client_id": verified.ClientID, "scope": verified.Scope, "exp": verified.Expires, "nbf": verified.NotBefore, "token_type": verified.TokenType, "broker_principal_type": verified.Kind},
	})
	return nil
}

func exactInspectionScopes(actual, expected string) bool {
	a, e := strings.Fields(actual), strings.Fields(expected)
	if len(a) != len(e) {
		return false
	}
	for _, scope := range e {
		if !contains(a, scope) {
			return false
		}
	}
	return true
}

// Decoding is for display only, after PF validation. Never use these maps as
// authentication input and never return a refresh token or token response body.
func inspectionClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 65536 {
		return nil, fail(502, "invalid_inspection_jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err != nil || len(payload) > 16<<10 || json.Unmarshal(payload, &claims) != nil || claims == nil {
		return nil, fail(502, "invalid_inspection_jwt")
	}
	return claims, nil
}
