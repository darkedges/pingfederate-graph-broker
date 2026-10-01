package main

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPortalUsesPublicPFRuntimeOnlyForBrowserAuthorization(t *testing.T) {
	publicURL, _ := url.Parse("https://portal.entraid.darkedges.com")
	privatePF, _ := url.Parse("https://localhost:9031")
	browserPF, _ := url.Parse("https://ping.entraid.darkedges.com")
	p := newPortal(config{publicURL: publicURL, pfURL: privatePF, pfBrowserURL: browserPF, clientID: "directory-portal"}, nil)
	server := httptest.NewServer(p.handler())
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(server.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != http.StatusSeeOther || location.Host != browserPF.Host ||
		location.Query().Get("redirect_uri") != "https://portal.entraid.darkedges.com/auth/callback" || p.c.pfURL.Host != privatePF.Host {
		t.Fatal("browser and back-channel PF origins were not kept separate")
	}
}

func TestReferenceCallbackRequiresPublicPFBrowserOrigin(t *testing.T) {
	publicURL, _ := url.Parse("https://portal.entraid.darkedges.com")
	privatePF, _ := url.Parse("https://localhost:9031")
	browserPF, _ := url.Parse("https://ping.entraid.darkedges.com")
	p := newPortal(config{publicURL: publicURL, pfURL: privatePF, pfBrowserURL: browserPF}, nil)
	for _, tc := range []struct {
		origin string
		status int
	}{
		{origin: "https://localhost:9031", status: http.StatusForbidden},
		{origin: "https://ping.entraid.darkedges.com", status: http.StatusUnauthorized},
	} {
		r := httptest.NewRequest(http.MethodPost, "https://portal.entraid.darkedges.com/auth/reference-callback", strings.NewReader("REF=test"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		p.handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("origin %q: got %d, want %d", tc.origin, w.Code, tc.status)
		}
	}
}

func TestConnectionMethodsBoundToAuthenticatedSubject(t *testing.T) {
	publicURL, _ := url.Parse("https://portal.entraid.darkedges.com")
	startURL, _ := url.Parse("https://ping.entraid.darkedges.com/sp/startSSO.ping")
	p := newPortal(config{publicURL: publicURL, startURL: startURL, samlConnectEnabled: true, referenceSubject: "broker-dev-user", samlSubject: "nirving@ping.darkedges.com"}, nil)
	for _, tc := range []struct {
		id, subject, allowed, denied string
	}{
		{"reference", "broker-dev-user", "/connect", "/connect/saml"},
		{"saml", "nirving@ping.darkedges.com", "/connect/saml", "/connect"},
	} {
		p.sessions[tc.id] = &session{subject: tc.subject, csrf: "csrf", expires: time.Now().Add(time.Hour)}
		sessionReq := httptest.NewRequest(http.MethodGet, "https://portal.entraid.darkedges.com/api/session", nil)
		sessionReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: tc.id})
		w := httptest.NewRecorder()
		p.handler().ServeHTTP(w, sessionReq)
		var state struct{ CanConnect, CanSamlConnect bool }
		if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		if state.CanConnect != (tc.allowed == "/connect") || state.CanSamlConnect != (tc.allowed == "/connect/saml") {
			t.Fatalf("wrong methods for %s: %+v", tc.subject, state)
		}
		r := httptest.NewRequest(http.MethodPost, "https://portal.entraid.darkedges.com"+tc.denied, strings.NewReader("csrf=csrf"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://portal.entraid.darkedges.com")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tc.id})
		w = httptest.NewRecorder()
		p.handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s used forbidden path %s: %d", tc.subject, tc.denied, w.Code)
		}
	}
}

func TestPortalLogoutClearsSessionAndStartsPFLogout(t *testing.T) {
	publicURL, _ := url.Parse("https://portal.entraid.darkedges.com")
	privatePF, _ := url.Parse("https://localhost:9031")
	browserPF, _ := url.Parse("https://ping.entraid.darkedges.com")
	p := newPortal(config{publicURL: publicURL, pfURL: privatePF, pfBrowserURL: browserPF, clientID: "directory-portal"}, nil)
	p.sessions["test-session"] = &session{csrf: "test-csrf", expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodPost, "https://portal.entraid.darkedges.com/logout", strings.NewReader("csrf=test-csrf"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://portal.entraid.darkedges.com")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	w := httptest.NewRecorder()
	p.handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self'") || !strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("logout status: %d", w.Code)
	}
	link := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(link) != 2 {
		t.Fatal("logout continuation link missing")
	}
	location, err := url.Parse(html.UnescapeString(link[1]))
	if err != nil || location.Scheme != "https" || location.Host != browserPF.Host || location.Path != "/idp/init_logout.openid" ||
		location.Query().Get("client_id") != "directory-portal" || location.Query().Get("post_logout_redirect_uri") != "https://portal.entraid.darkedges.com/" {
		t.Fatal("unexpected logout destination")
	}
	if len(p.sessions) != 0 || len(w.Result().Cookies()) == 0 || w.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatal("portal session was not cleared")
	}

	p.sessions["test-session"] = &session{csrf: "test-csrf", expires: time.Now().Add(time.Hour)}
	bad := httptest.NewRequest(http.MethodPost, "https://portal.entraid.darkedges.com/logout", strings.NewReader("csrf=wrong"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	denied := httptest.NewRecorder()
	p.handler().ServeHTTP(denied, bad)
	if denied.Code != http.StatusForbidden || len(p.sessions) != 1 {
		t.Fatal("invalid CSRF request changed portal session")
	}
}

func TestPortalConnectFlow(t *testing.T) {
	var verifier atomic.Value
	pf := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/as/token.oauth2" {
			t.Errorf("unexpected PF path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "directory-portal" || pass != "test-secret" {
			t.Error("incorrect PF client auth")
		}
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code") != "good-code" || r.FormValue("redirect_uri") != "https://localhost:8788/auth/callback" || r.FormValue("code_verifier") != verifier.Load() {
			t.Error("incorrect code exchange")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"server-only-token","token_type":"Bearer","expires_in":900}`)
	}))
	defer pf.Close()
	var begins, completes atomic.Int32
	completionStarted := make(chan struct{})
	completionReleased := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(completionReleased) }) }
	defer release()
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer server-only-token" {
			t.Error("broker did not receive server-side bearer token")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/me":
			_ = json.NewEncoder(w).Encode(map[string]string{"subject": "broker-dev-user"})
		case "/v1/link-intents":
			begins.Add(1)
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"intent_id": "intent-1", "expires_at": time.Now().Add(time.Minute)})
		case "/v1/link-intents/intent-1/complete":
			completes.Add(1)
			close(completionStarted)
			<-completionReleased
			var body struct {
				Reference string `json:"reference"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Reference != "one-time-ref" {
				t.Error("wrong reference")
			}
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"connection_id":"connection-1"}`)
		default:
			t.Errorf("unexpected broker path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer broker.Close()
	defer release() // Unblock the mock before its server is closed on test failure.
	publicURL, _ := url.Parse("https://localhost:8788")
	pfURL, _ := url.Parse(pf.URL)
	brokerURL, _ := url.Parse(broker.URL)
	startURL, _ := url.Parse(pf.URL + "/idp/startSSO.ping?PartnerSpId=graphDirectoryLink")
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := newPortal(config{publicURL: publicURL, pfURL: pfURL, brokerURL: brokerURL, startURL: startURL, clientID: "directory-portal", clientSecret: "test-secret", referenceSubject: "broker-dev-user", samlSubject: "nirving@ping.darkedges.com"}, logger)
	p.client = pf.Client()
	p.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	server := httptest.NewTLSServer(p.handler())
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	browser := server.Client()
	browser.Jar = jar
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	get := func(path string) *http.Response {
		t.Helper()
		resp, err := browser.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	login := get("/auth/login")
	if login.StatusCode != 303 {
		t.Fatalf("login: %d", login.StatusCode)
	}
	authorize, err := url.Parse(login.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if authorize.Host != pfURL.Host || authorize.Query().Get("code_challenge_method") != "S256" || authorize.Query().Get("scope") != "broker.connect" {
		t.Fatal("invalid authorization request")
	}
	login.Body.Close()
	bad := get("/auth/callback?code=good-code&state=bad")
	if bad.StatusCode != 400 {
		t.Fatalf("bad state accepted: %d", bad.StatusCode)
	}
	bad.Body.Close()
	login = get("/auth/login")
	authorize, _ = url.Parse(login.Header.Get("Location"))
	login.Body.Close()
	state := authorize.Query().Get("state")
	p.mu.Lock()
	for _, v := range p.logins {
		if v.state == state {
			verifier.Store(v.verifier)
		}
	}
	p.mu.Unlock()
	if verifier.Load() == nil {
		t.Fatal("missing PKCE verifier")
	}
	callback := get("/auth/callback?code=good-code&state=" + url.QueryEscape(state))
	if callback.StatusCode != 303 {
		t.Fatalf("callback: %d", callback.StatusCode)
	}
	callback.Body.Close()
	page := get("/legacy")
	if got := page.Header.Get("Referrer-Policy"); got != "origin" {
		t.Fatalf("form referrer policy: %q", got)
	}
	home, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if strings.Contains(string(home), "server-only-token") || !strings.Contains(string(home), "Connect Microsoft") {
		t.Fatal("token leaked or portal unavailable")
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(string(home))
	if len(csrf) != 2 {
		t.Fatal("missing CSRF form")
	}
	post := func(path string, values url.Values, source string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", source)
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	unsolicited := post("/auth/reference-callback", url.Values{"REF": {"one-time-ref"}}, pf.URL)
	if unsolicited.StatusCode != 409 {
		t.Fatalf("unsolicited reference: %d", unsolicited.StatusCode)
	}
	unsolicited.Body.Close()
	queryMode := get("/auth/reference-callback?REF=one-time-ref")
	if queryMode.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("query-mode reference accepted: %d", queryMode.StatusCode)
	}
	queryMode.Body.Close()
	withoutIntent := get("/connect/continue")
	if withoutIntent.StatusCode != 303 || withoutIntent.Header.Get("Location") != "/" {
		t.Fatalf("unsolicited continue: %d", withoutIntent.StatusCode)
	}
	withoutIntent.Body.Close()
	badConnect := post("/connect", url.Values{"csrf": {"wrong"}}, "https://localhost:8788")
	if badConnect.StatusCode != 403 {
		t.Fatalf("bad csrf: %d", badConnect.StatusCode)
	}
	badConnect.Body.Close()
	nullOrigin := post("/connect", url.Values{"csrf": {csrf[1]}}, "null")
	if nullOrigin.StatusCode != 403 {
		t.Fatalf("null origin accepted: %d", nullOrigin.StatusCode)
	}
	nullOrigin.Body.Close()
	connect := post("/connect", url.Values{"csrf": {csrf[1]}}, "https://localhost:8788")
	if connect.StatusCode != 303 || connect.Header.Get("Location") != "/connect/continue" {
		t.Fatalf("connect: %d %s", connect.StatusCode, connect.Header.Get("Location"))
	}
	connect.Body.Close()
	continuePage := get("/connect/continue")
	continueBody, _ := io.ReadAll(continuePage.Body)
	continuePage.Body.Close()
	if continuePage.StatusCode != 200 || !strings.Contains(html.UnescapeString(string(continueBody)), `href="`+startURL.String()+`"`) || strings.Contains(string(continueBody), "#ZgotmplZ") || strings.Contains(string(continueBody), "server-only-token") {
		t.Fatal("PF journey continuation page is invalid or leaks a token")
	}
	if !strings.Contains(string(continueBody), `http-equiv="refresh"`) || !strings.Contains(continuePage.Header.Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatal("PF journey continuation must be a separate navigation with restricted form policy")
	}
	page = get("/legacy")
	home, _ = io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(home), "Waiting for Microsoft sign-in") || !strings.Contains(string(home), "Continue Microsoft sign-in") || strings.Contains(string(home), "<button>Connect Microsoft</button>") {
		t.Fatal("pending connection state not shown")
	}
	badOrigin := post("/auth/reference-callback", url.Values{"REF": {"one-time-ref"}}, "https://evil.example")
	if badOrigin.StatusCode != 403 {
		t.Fatalf("bad origin: %d", badOrigin.StatusCode)
	}
	badOrigin.Body.Close()
	extraField := post("/auth/reference-callback", url.Values{"REF": {"one-time-ref"}, "TARGET": {"private-extra-value"}}, pf.URL)
	if extraField.StatusCode != 400 {
		t.Fatalf("unexpected form field accepted: %d", extraField.StatusCode)
	}
	extraField.Body.Close()
	wrongTarget := post("/auth/reference-callback", url.Values{"REF": {"one-time-ref"}, "TargetResource": {"https://evil.example/redirect"}}, pf.URL)
	if wrongTarget.StatusCode != 400 {
		t.Fatalf("mismatched target resource accepted: %d", wrongTarget.StatusCode)
	}
	wrongTarget.Body.Close()
	complete := post("/auth/reference-callback", url.Values{"REF": {"one-time-ref"}, "TargetResource": {"https://localhost:8788/auth/reference-callback"}}, pf.URL)
	if complete.StatusCode != 303 {
		t.Fatalf("complete: %d", complete.StatusCode)
	}
	complete.Body.Close()
	select {
	case <-completionStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("connection completion did not start")
	}
	page = get("/legacy")
	home, _ = io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(home), "Connecting to Microsoft") || !strings.Contains(string(home), "<progress") {
		t.Fatal("connection progress not shown")
	}
	replay := post("/auth/reference-callback", url.Values{"REF": {"one-time-ref"}}, pf.URL)
	if replay.StatusCode != 409 {
		t.Fatalf("replay: %d", replay.StatusCode)
	}
	replay.Body.Close()
	release()
	var connected bool
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		page = get("/legacy")
		home, _ = io.ReadAll(page.Body)
		page.Body.Close()
		if strings.Contains(string(home), "connection-1") {
			connected = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !connected || strings.Contains(string(home), "server-only-token") {
		t.Fatal("connection metadata not shown safely")
	}
	if begins.Load() != 1 || completes.Load() != 1 {
		t.Fatalf("broker call counts: %d, %d", begins.Load(), completes.Load())
	}
	for _, event := range []string{"reference_intent_created", "reference_callback_received", "reference_callback_rejected", "reference_callback_accepted", "reference_completion_started", "reference_completion_finished"} {
		if !strings.Contains(logs.String(), event) {
			t.Fatalf("missing debug event %s", event)
		}
	}
	if !strings.Contains(logs.String(), `"reason":"unexpected_form_fields"`) {
		t.Fatal("missing safe rejection reason for extra form field")
	}
	if !strings.Contains(logs.String(), `"reason":"target_resource_mismatch"`) {
		t.Fatal("missing safe rejection reason for mismatched target resource")
	}
	for _, secret := range []string{"one-time-ref", "server-only-token", "intent-1", "good-code", "csrf-value", "private-extra-value"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("debug logs contain a sensitive value")
		}
	}
	p.mu.Lock()
	for _, live := range p.sessions {
		live.intent = "abandoned-intent"
		live.intentExpires = time.Now().Add(-time.Second)
	}
	p.mu.Unlock()
	page = get("/legacy")
	home, _ = io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(home), "<button>Connect Microsoft</button>") || strings.Contains(string(home), "Waiting for Microsoft sign-in") {
		t.Fatal("expired connection intent did not clear")
	}
	expiredContinue := get("/connect/continue")
	if expiredContinue.StatusCode != 303 || expiredContinue.Header.Get("Location") != "/" {
		t.Fatalf("expired intent continued: %d", expiredContinue.StatusCode)
	}
	expiredContinue.Body.Close()
}

func TestReferenceFormFailure(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{"missing", url.Values{"other": {"value"}}, "reference_missing"},
		{"duplicate", url.Values{"REF": {"one", "two"}}, "reference_duplicate"},
		{"empty", url.Values{"REF": {""}}, "reference_empty"},
		{"oversized", url.Values{"REF": {strings.Repeat("x", 2049)}}, "reference_oversized"},
		{"extra", url.Values{"REF": {"one"}, "other": {"value"}}, "unexpected_form_fields"},
		{"too many", url.Values{"REF": {"one"}, "TargetResource": {"https://localhost:8788/auth/reference-callback"}, "other": {"value"}}, "unexpected_form_fields"},
		{"wrong target", url.Values{"REF": {"one"}, "TargetResource": {"https://evil.example/redirect"}}, "target_resource_mismatch"},
		{"duplicate target", url.Values{"REF": {"one"}, "TargetResource": {"https://localhost:8788/auth/reference-callback", "https://localhost:8788/auth/reference-callback"}}, "target_resource_mismatch"},
		{"valid target", url.Values{"REF": {"one"}, "TargetResource": {"https://localhost:8788/auth/reference-callback"}}, ""},
		{"valid", url.Values{"REF": {"one"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := referenceFormFailure(tt.form, "https://localhost:8788/auth/reference-callback"); got != tt.want {
				t.Fatalf("failure reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPortalCompletionFailureAllowsRetry(t *testing.T) {
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer broker.Close()
	brokerURL, _ := url.Parse(broker.URL)
	startURL, _ := url.Parse("https://localhost:9031/sp/startSSO.ping")
	p := newPortal(config{brokerURL: brokerURL, startURL: startURL, referenceSubject: "broker-dev-user"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.sessions["session-id"] = &session{token: "server-only-token", csrf: "csrf-value", subject: "broker-dev-user", expires: time.Now().Add(time.Minute), busy: true}
	p.completeConnection("session-id", "server-only-token", "intent-id", "one-time-ref")
	server := httptest.NewTLSServer(p.handler())
	defer server.Close()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/legacy", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-id"})
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(page), "Connection failed. You can try again.") || !strings.Contains(string(page), "<button>Connect Microsoft</button>") || strings.Contains(string(page), "server-only-token") {
		t.Fatal("failed completion did not offer a safe retry")
	}
}
