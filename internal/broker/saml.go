package broker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	pfExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	saml11Type      = "urn:ietf:params:oauth:token-type:saml1"
	accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
	saml11Grant     = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
	oboGrant        = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

var aadstsCodePattern = regexp.MustCompile(`AADSTS([0-9]{5,7})`)

// Only a numeric Entra error category is retained. Never log the response
// body or error_description, which can include request or account details.
func aadstsErrorCode(body []byte) string {
	var response struct {
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &response) != nil {
		return ""
	}
	match := aadstsCodePattern.FindStringSubmatch(response.Description)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

type tokenClaims struct {
	Audience any    `json:"aud"`
	Tenant   string `json:"tid"`
	Object   string `json:"oid"`
	Scopes   string `json:"scp"`
	Expires  int64  `json:"exp"`
}

// Tokens here are obtained directly from the configured Entra HTTPS token
// endpoint, never accepted from a caller. Claims are checked again before
// use; no token, assertion, or upstream body enters logs or responses.
func parseTokenClaims(raw string) (tokenClaims, error) {
	var claims tokenClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 65536 {
		return claims, fail(502, "invalid_entra_token_response")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) > 16<<10 || json.Unmarshal(payload, &claims) != nil {
		return claims, fail(502, "invalid_entra_token_response")
	}
	return claims, nil
}

func (c tokenClaims) hasAudience(want string) bool {
	switch a := c.Audience.(type) {
	case string:
		return strings.EqualFold(a, want)
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && strings.EqualFold(s, want) {
				return true
			}
		}
	}
	return false
}

// Entra can report the requested /.default selector instead of the expanded
// delegated scopes in the OBO response. Only the JWT's scp claim can then
// establish the actual permissions; samlConnect checks it before persistence.
func validateGraphOBOResponse(t TokenResponse) error {
	if t.AccessToken == "" || !strings.EqualFold(t.TokenType, "Bearer") || t.ExpiresIn <= 0 || t.ExpiresIn > 86400 {
		return fail(502, "invalid_entra_token_response")
	}
	// /.default names the permission set requested, not an additional
	// permission. Some responses include it alongside the expanded scopes.
	var expanded []string
	for _, scope := range strings.Fields(t.Scope) {
		if scope != GraphOBOScope {
			expanded = append(expanded, scope)
		}
	}
	if len(expanded) > 0 && validateGraphScopes(strings.Join(expanded, " ")) != nil {
		return fail(409, "unexpected_entra_permissions")
	}
	return nil
}

// Report only fixed categories, never the upstream scope string itself.
func graphScopeDiagnostics(scope string) (bool, bool, bool, bool) {
	var basic, group, selector, other bool
	for _, value := range strings.Fields(scope) {
		if value == GraphOBOScope {
			selector = true
			continue
		}
		value = strings.TrimPrefix(value, "https://graph.microsoft.com/")
		switch value {
		case "User.ReadBasic.All":
			basic = true
		case "GroupMember.Read.All":
			group = true
		case "openid", "profile", "email", "offline_access", "User.Read":
		default:
			other = true
		}
	}
	return basic, group, selector, other
}

func (b *Broker) exchangeForm(ctx context.Context, endpoint string, values url.Values, stage string) (TokenResponse, error) {
	var out TokenResponse
	req, err := formRequest(ctx, endpoint, values)
	if err != nil {
		return out, fail(502, "token_exchange_unavailable")
	}
	res, err := b.http.Do(req)
	if err != nil {
		return out, fail(502, "token_exchange_unavailable")
	}
	defer res.Body.Close()
	data, err := readLimited(res.Body, 256<<10)
	if err != nil {
		return out, fail(502, "token_exchange_unavailable")
	}
	if res.StatusCode != http.StatusOK {
		b.log.Debug("saml_token_endpoint_rejected", "stage", stage, "status", res.StatusCode, "aadsts_code", aadstsErrorCode(data))
		return out, fail(502, "token_exchange_rejected")
	}
	if json.Unmarshal(data, &out) != nil || out.AccessToken == "" || out.ExpiresIn < 1 || out.ExpiresIn > 86400 {
		return TokenResponse{}, fail(502, "invalid_token_exchange_response")
	}
	return out, nil
}

func (b *Broker) samlConnect(w http.ResponseWriter, r *http.Request, p Principal) error {
	cfg := b.cfg.SAML
	if !cfg.Enabled() {
		return fail(503, "saml_connection_not_configured")
	}
	if p.Subject != cfg.ExpectedPFSubject {
		return fail(403, "saml_subject_not_allowed")
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 {
		return fail(401, "invalid_token")
	}
	// The subject token is the already-introspected portal access token. The
	// dedicated PF exchange policy must validate it as an access token and
	// issue a SAML 1.1 assertion only for the intended subject.
	pf, err := b.exchangeForm(r.Context(), cfg.PFTokenURL, url.Values{
		"grant_type": {pfExchangeGrant}, "subject_token": {parts[1]}, "subject_token_type": {accessTokenType},
		"requested_token_type": {saml11Type}, "client_id": {cfg.PFClientID}, "client_secret": {cfg.PFClientSecret},
	}, "pingfederate")
	if err != nil {
		b.log.Debug("saml_exchange", "stage", "pingfederate", "outcome", "failed")
		return err
	}
	if pf.TokenType != "N_A" || pf.IssuedTokenType != saml11Type {
		b.log.Debug("saml_exchange", "stage", "pingfederate", "outcome", "invalid_response")
		return fail(502, "invalid_pf_assertion")
	}
	intermediate, err := b.exchangeForm(r.Context(), cfg.TokenURL, url.Values{
		"grant_type": {saml11Grant}, "assertion": {pf.AccessToken}, "client_id": {cfg.SAMLClientID},
		"client_secret": {cfg.SAMLClientSecret}, "scope": {cfg.Scope},
	}, "entra_saml_bearer")
	if err != nil {
		b.log.Debug("saml_exchange", "stage", "entra_saml_bearer", "outcome", "failed")
		return err
	}
	if !strings.EqualFold(intermediate.TokenType, "Bearer") {
		b.log.Debug("saml_exchange", "stage", "entra_saml_bearer", "outcome", "invalid_response")
		return fail(502, "invalid_entra_token_response")
	}
	apiClaims, err := parseTokenClaims(intermediate.AccessToken)
	if err != nil {
		return err
	}
	apiScope, _ := url.Parse(strings.Fields(cfg.Scope)[0])
	if apiScope == nil || !apiClaims.hasAudience(apiScope.Host) ||
		!strings.EqualFold(apiClaims.Tenant, cfg.TenantID) || !strings.EqualFold(apiClaims.Object, cfg.ExpectedEntraOID) ||
		apiClaims.Scopes != "access_as_user" || apiClaims.Expires <= time.Now().Unix() {
		return fail(403, "saml_identity_mismatch")
	}
	graph, err := b.exchangeForm(r.Context(), cfg.TokenURL, url.Values{
		"grant_type": {oboGrant}, "requested_token_use": {"on_behalf_of"}, "assertion": {intermediate.AccessToken},
		"client_id": {cfg.OBOClientID}, "client_secret": {cfg.OBOClientSecret}, "scope": {GraphOBOScope},
	}, "entra_graph_obo")
	if err != nil {
		b.log.Debug("saml_exchange", "stage", "entra_graph_obo", "outcome", "failed")
		return err
	}
	if err := validateGraphOBOResponse(graph); err != nil {
		basic, group, selector, other := graphScopeDiagnostics(graph.Scope)
		b.log.Debug("saml_exchange", "stage", "entra_graph_obo", "outcome", "response_rejected",
			"scope_is_default", graph.Scope == GraphOBOScope, "scope_is_empty", graph.Scope == "",
			"has_user_read_basic", basic, "has_group_member_read", group,
			"has_default_selector", selector, "has_other_scope", other)
		return err
	}
	claims, err := parseTokenClaims(graph.AccessToken)
	if err != nil {
		return err
	}
	audienceOK := claims.hasAudience("https://graph.microsoft.com")
	tenantOK := strings.EqualFold(claims.Tenant, cfg.TenantID)
	userOK := strings.EqualFold(claims.Object, cfg.ExpectedEntraOID)
	expiryOK := claims.Expires > time.Now().Add(90*time.Second).Unix()
	scopesOK := validateGraphScopes(claims.Scopes) == nil
	if !audienceOK || !tenantOK || !userOK || !expiryOK || !scopesOK {
		b.log.Debug("saml_exchange", "stage", "entra_graph_obo", "outcome", "claims_rejected",
			"audience_ok", audienceOK, "tenant_ok", tenantOK, "user_ok", userOK,
			"expiry_ok", expiryOK, "scopes_ok", scopesOK)
		return fail(403, "unexpected_entra_permissions")
	}
	// A SAML-bearer/OBO exchange does not yield a refresh token. It is a
	// deliberately short-lived connection; never try the refresh-token path.
	graph.RefreshToken = ""
	connection := Connection{ID: newID(), Owner: p.Subject, TenantID: cfg.TenantID, ObjectID: cfg.ExpectedEntraOID,
		ClientID: cfg.OBOClientID, Mode: "saml", CreatedAt: time.Now()}
	applyTokens(&connection, graph)
	if expiry := time.Unix(claims.Expires, 0); expiry.Before(connection.ExpiresAt) {
		connection.ExpiresAt = expiry
	}
	if err := b.store.Update(func(s *State) error {
		count := 0
		for _, existing := range s.Connections {
			if existing.Owner == p.Subject {
				count++
			}
		}
		if count >= 10 {
			return fail(409, "connection_limit_reached")
		}
		s.Connections[connection.ID] = connection
		return nil
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, connectionSummary(connection))
	return nil
}
