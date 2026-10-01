package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type apiError struct {
	status int
	code   string
}

func (e *apiError) Error() string        { return e.code }
func fail(status int, code string) error { return &apiError{status, code} }

func outboundClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, errors.New("response too large")
	}
	return b, nil
}
func formRequest(ctx context.Context, endpoint string, form url.Values) (*http.Request, error) {
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if e == nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return r, e
}

type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

type Principal struct {
	Active    bool       `json:"active"`
	Subject   string     `json:"sub"`
	ClientID  string     `json:"client_id"`
	Issuer    string     `json:"iss"`
	Audience  stringList `json:"aud"`
	Expires   int64      `json:"exp"`
	NotBefore int64      `json:"nbf"`
	Scope     string     `json:"scope"`
	TokenType string     `json:"token_type"`
	Kind      string     `json:"broker_principal_type"`
}

func (b *Broker) authenticate(r *http.Request, kind, scope string) (Principal, error) {
	var p Principal
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 32768 {
		return p, fail(401, "invalid_token")
	}
	req, e := formRequest(r.Context(), b.cfg.PFIntrospectionURL, url.Values{"token": {parts[1]}, "token_type_hint": {"access_token"}})
	if e != nil {
		return p, fail(503, "identity_service_unavailable")
	}
	req.SetBasicAuth(b.cfg.PFClientID, b.cfg.PFClientSecret)
	res, e := b.http.Do(req)
	if e != nil {
		return p, fail(503, "identity_service_unavailable")
	}
	defer res.Body.Close()
	body, e := readLimited(res.Body, 128<<10)
	if e != nil || res.StatusCode != 200 || json.Unmarshal(body, &p) != nil {
		return p, fail(503, "identity_service_unavailable")
	}
	if !p.Active || p.Expires <= time.Now().Unix() || p.NotBefore > time.Now().Unix() || p.Issuer != b.cfg.PFIssuer || !contains(p.Audience, b.cfg.Audience) || !strings.EqualFold(p.TokenType, "Bearer") || p.ClientID == "" {
		return p, fail(401, "invalid_token")
	}
	if p.Kind != kind || !contains(strings.Fields(p.Scope), scope) {
		return p, fail(403, "insufficient_authority")
	}
	if kind == "user" && (!contains(b.cfg.PortalClients, p.ClientID) || p.Subject == "") {
		return p, fail(403, "untrusted_portal")
	}
	if kind == "agent" && !contains(b.cfg.AgentClients, p.ClientID) {
		return p, fail(403, "untrusted_agent")
	}
	return p, nil
}

type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	TokenType       string `json:"token_type"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

// parsePickedTokenResponse accepts a bounded JSON number or a canonical
// decimal integer string for expires_in from PF Agentless pickup. Fractional
// numbers are rounded down so the broker never extends the token lifetime.
// This compatibility rule applies only to PF pickup, not Entra refresh.
func parsePickedTokenResponse(raw []byte) (TokenResponse, error) {
	var result TokenResponse
	var wire struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		TokenType    string          `json:"token_type"`
		ExpiresIn    json.RawMessage `json:"expires_in"`
		Scope        string          `json:"scope"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return result, err
	}
	if len(wire.ExpiresIn) != 0 {
		if wire.ExpiresIn[0] == '"' {
			var text string
			if err := json.Unmarshal(wire.ExpiresIn, &text); err != nil {
				return result, err
			}
			seconds, err := strconv.ParseInt(text, 10, 64)
			if err != nil || strconv.FormatInt(seconds, 10) != text {
				return result, errors.New("invalid pickup expiry format")
			}
			result.ExpiresIn = seconds
		} else {
			var number json.Number
			if err := json.Unmarshal(wire.ExpiresIn, &number); err != nil {
				return result, err
			}
			seconds, err := strconv.ParseFloat(number.String(), 64)
			if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 1 || seconds > 86400 {
				return result, errors.New("invalid pickup expiry range")
			}
			result.ExpiresIn = int64(math.Floor(seconds))
		}
	}
	result.AccessToken = wire.AccessToken
	result.RefreshToken = wire.RefreshToken
	result.TokenType = wire.TokenType
	result.Scope = wire.Scope
	return result, nil
}

// tokenResponseFormatShape returns only fixed diagnostic categories. In
// particular, it must never include the picked-up token response or a raw
// parser error, either of which could contain credentials.
func tokenResponseFormatShape(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "missing"
	}
	if bytes.Equal(raw, []byte("null")) {
		return "null"
	}
	switch raw[0] {
	case '{':
		return tokenResponseObjectShape(raw)
	case '"':
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return "string_invalid"
		}
		return "string_" + embeddedTokenResponseShape(value)
	case '[':
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || len(values) != 1 {
			return "array_not_singleton"
		}
		var value string
		if json.Unmarshal(values[0], &value) != nil {
			return "array_non_string"
		}
		return "array_string_" + embeddedTokenResponseShape(value)
	default:
		return "unsupported_type"
	}
}

func embeddedTokenResponseShape(value string) string {
	raw := bytes.TrimSpace([]byte(value))
	if len(raw) == 0 {
		return "empty"
	}
	if !json.Valid(raw) {
		return "non_json"
	}
	if raw[0] != '{' {
		return "json_non_object"
	}
	return tokenResponseObjectShape(raw)
}

func tokenResponseObjectShape(raw []byte) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return "object_invalid"
	}
	for _, name := range []string{"access_token", "refresh_token", "token_type", "scope"} {
		if value, ok := fields[name]; ok {
			var text string
			if json.Unmarshal(value, &text) != nil {
				return "object_field_type_" + name
			}
		}
	}
	if value, ok := fields["expires_in"]; ok {
		if shape := pickupExpiryShape(value); shape != "integer" && shape != "decimal_string" {
			return "object_field_type_expires_in_" + shape
		}
	}
	return "object_other_type"
}

// pickupExpiryShape reports only fixed type/syntax categories, never the
// expiry value or any adjacent token fields from the pickup response.
func pickupExpiryShape(value json.RawMessage) string {
	value = bytes.TrimSpace(value)
	if len(value) == 0 {
		return "missing"
	}
	if bytes.Equal(value, []byte("null")) {
		return "null"
	}
	switch value[0] {
	case '"':
		var text string
		if json.Unmarshal(value, &text) != nil {
			return "invalid_string"
		}
		seconds, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return "non_decimal_string"
		}
		if strconv.FormatInt(seconds, 10) != text {
			return "noncanonical_decimal_string"
		}
		return "decimal_string"
	case '[':
		return "array"
	case '{':
		return "object"
	case 't', 'f':
		return "boolean"
	default:
		var seconds int64
		if json.Unmarshal(value, &seconds) != nil {
			return "non_integer_number"
		}
		return "integer"
	}
}

func (t TokenResponse) validate(requireRefresh bool) error {
	if t.AccessToken == "" || !strings.EqualFold(t.TokenType, "Bearer") || t.ExpiresIn <= 0 || t.ExpiresIn > 86400 || requireRefresh && t.RefreshToken == "" {
		return fail(502, "invalid_entra_token_response")
	}
	if validateGraphScopes(t.Scope) != nil {
		return fail(409, "unexpected_entra_permissions")
	}
	return nil
}

type PickedTokens struct {
	Owner, TenantID, ObjectID string
	Tokens                    TokenResponse
}

func (b *Broker) pickup(ctx context.Context, reference string) (PickedTokens, error) {
	var p PickedTokens
	if reference == "" || len(reference) > 2048 {
		b.log.Debug("reference_pickup", "stage", "input", "outcome", "invalid_reference")
		return p, fail(400, "invalid_reference")
	}
	b.log.Debug("reference_pickup", "stage", "request", "outcome", "started")
	u, e := url.Parse(b.cfg.PFPickupURL)
	if e != nil {
		b.log.Debug("reference_pickup", "stage", "request", "outcome", "configuration_error")
		return p, fail(502, "pickup_failed")
	}
	q := u.Query()
	q.Set("REF", reference)
	u.RawQuery = q.Encode()
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		b.log.Debug("reference_pickup", "stage", "request", "outcome", "construction_error")
		return p, fail(502, "pickup_failed")
	}
	r.SetBasicAuth(b.cfg.PFPickupUser, b.cfg.PFPickupPassword)
	r.Header.Set("ping.instanceId", b.cfg.PFAdapterID)
	res, e := b.http.Do(r)
	if e != nil {
		// The transport error may embed the pickup URL and REF query; omit it.
		b.log.Debug("reference_pickup", "stage", "request", "outcome", "transport_error")
		return p, fail(502, "pickup_failed")
	}
	defer res.Body.Close()
	body, e := readLimited(res.Body, 256<<10)
	if e != nil {
		b.log.Debug("reference_pickup", "stage", "response", "outcome", "read_error", "status", res.StatusCode)
		return p, fail(502, "pickup_failed")
	}
	if res.StatusCode != 200 {
		b.log.Debug("reference_pickup", "stage", "response", "outcome", "http_error", "status", res.StatusCode)
		return p, fail(502, "pickup_failed")
	}
	var attrs map[string]json.RawMessage
	if json.Unmarshal(body, &attrs) != nil {
		b.log.Debug("reference_pickup", "stage", "payload", "outcome", "invalid_json")
		return p, fail(502, "invalid_pickup_response")
	}
	for name, dest := range map[string]*string{"subject": &p.Owner, "entra_tid": &p.TenantID, "entra_oid": &p.ObjectID} {
		var values stringList
		if json.Unmarshal(attrs[name], &values) != nil || len(values) != 1 || values[0] == "" {
			b.log.Debug("reference_pickup", "stage", "payload", "outcome", "invalid_attribute", "attribute", name)
			return p, fail(502, "invalid_pickup_attributes")
		}
		*dest = values[0]
	}
	raw := bytes.TrimSpace(attrs["entra_token_response"])
	// Support a JSON object, a JSON string, or a singleton string array, as configured in PF.
	if len(raw) > 0 && raw[0] != '{' {
		var values stringList
		if json.Unmarshal(raw, &values) != nil || len(values) != 1 {
			b.log.Debug("reference_pickup", "stage", "payload", "outcome", "invalid_token_response_format", "format_shape", tokenResponseFormatShape(attrs["entra_token_response"]))
			return p, fail(502, "invalid_pickup_attributes")
		}
		raw = []byte(values[0])
	}
	if p.Tokens, e = parsePickedTokenResponse(raw); e != nil {
		b.log.Debug("reference_pickup", "stage", "payload", "outcome", "invalid_token_response_format", "format_shape", tokenResponseFormatShape(attrs["entra_token_response"]))
		return p, fail(502, "invalid_pickup_attributes")
	}
	if !strings.EqualFold(p.TenantID, b.cfg.TenantID) || !guid.MatchString(p.ObjectID) {
		b.log.Debug("reference_pickup", "stage", "identity", "outcome", "mismatch")
		return p, fail(403, "wrong_entra_identity")
	}
	if e = p.Tokens.validate(true); e != nil {
		b.log.Debug("reference_pickup", "stage", "tokens", "outcome", "validation_failed")
		return p, e
	}
	b.log.Debug("reference_pickup", "stage", "complete", "outcome", "validated")
	return p, nil
}

func (b *Broker) refresh(ctx context.Context, c Connection) (TokenResponse, error) {
	var t TokenResponse
	r, e := formRequest(ctx, b.cfg.EntraTokenURL, url.Values{"grant_type": {"refresh_token"}, "client_id": {b.cfg.EntraClientID}, "client_secret": {b.cfg.EntraClientSecret}, "refresh_token": {c.RefreshToken}, "scope": {GraphScopes}})
	if e != nil {
		return t, fail(502, "entra_unavailable")
	}
	res, e := b.http.Do(r)
	if e != nil {
		return t, fail(502, "entra_unavailable")
	}
	defer res.Body.Close()
	body, e := readLimited(res.Body, 256<<10)
	if e != nil {
		return t, fail(502, "entra_unavailable")
	}
	if res.StatusCode != 200 {
		var oauth struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &oauth)
		switch oauth.Error {
		case "invalid_grant", "interaction_required", "consent_required", "login_required":
			return t, fail(409, "reconnect_required")
		}
		if res.StatusCode == 429 || res.StatusCode >= 500 {
			return t, fail(503, "entra_temporarily_unavailable")
		}
		return t, fail(502, "entra_refresh_failed")
	}
	if json.Unmarshal(body, &t) != nil {
		return t, fail(502, "invalid_entra_token_response")
	}
	return t, t.validate(false)
}

type DirectoryObject struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName,omitempty"`
	Mail              string `json:"mail,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	Type              string `json:"@odata.type,omitempty"`
}
type graphPage struct {
	Value    []DirectoryObject `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}
type Page struct {
	Items      []DirectoryObject `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

func (b *Broker) graphGET(ctx context.Context, target, accessToken string) (graphPage, error) {
	var page graphPage
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if e != nil {
		return page, fail(502, "graph_unavailable")
	}
	r.Header.Set("Authorization", "Bearer "+accessToken)
	res, e := b.http.Do(r)
	if e != nil {
		return page, fail(502, "graph_unavailable")
	}
	defer res.Body.Close()
	body, e := readLimited(res.Body, 2<<20)
	if e != nil {
		return page, fail(502, "graph_response_too_large")
	}
	switch res.StatusCode {
	case 200:
		if json.Unmarshal(body, &page) != nil || page.Value == nil || len(page.Value) > 100 {
			return page, fail(502, "invalid_graph_response")
		}
		return page, nil
	case 401:
		return page, fail(409, "reconnect_required")
	case 403:
		return page, fail(403, "graph_access_denied")
	case 404:
		return page, fail(404, "directory_object_not_found")
	case 429:
		return page, fail(429, "graph_throttled")
	default:
		return page, fail(502, "graph_unavailable")
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return fail(415, "application_json_required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return fail(400, "invalid_json")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fail(400, "invalid_json")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, e error) {
	var a *apiError
	if !errors.As(e, &a) {
		a = &apiError{500, "internal_error"}
	}
	if a.status == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="directory-broker"`)
	}
	if a.status == 429 {
		w.Header().Set("Retry-After", strconv.Itoa(30))
	}
	writeJSON(w, a.status, map[string]string{"error": a.code})
}
