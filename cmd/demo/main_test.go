package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDemoLifecycleOverHTTP(t *testing.T) {
	d, err := newDemo()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.close)
	srv := httptest.NewServer(d.Handler())
	t.Cleanup(srv.Close)

	call := func(method, path string, want int) map[string]any {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var result map[string]any
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: got %d, expected %d: %v", method, path, res.StatusCode, want, result)
		}
		return result
	}

	call(http.MethodGet, "/healthz", 200)
	call(http.MethodGet, "/demo/state", 200)
	connected := call(http.MethodPost, "/demo/connect", 201)
	if connected["status"] != "active" || connected["access_token"] != nil || connected["refresh_token"] != nil {
		t.Fatalf("invalid connection metadata: %v", connected)
	}
	delegated := call(http.MethodPost, "/demo/delegate", 201)
	if delegated["delegation_id"] == "" {
		t.Fatal("delegation missing")
	}
	first := call(http.MethodGet, "/demo/read?kind=users", 200)
	if len(first["items"].([]any)) != 2 || first["next_cursor"] == "" {
		t.Fatalf("expected first user page and cursor: %v", first)
	}
	second := call(http.MethodGet, "/demo/read?kind=users&cursor="+url.QueryEscape(first["next_cursor"].(string)), 200)
	if len(second["items"].([]any)) != 1 || second["next_cursor"] != nil {
		t.Fatalf("expected final user page: %v", second)
	}
	groups := call(http.MethodGet, "/demo/read?kind=groups&prefix=Eng", 200)
	if len(groups["items"].([]any)) != 1 {
		t.Fatalf("group search failed: %v", groups)
	}
	call(http.MethodGet, "/demo/read?kind=members", 200)
	call(http.MethodPost, "/demo/revoke", 200)
	call(http.MethodGet, "/demo/read?kind=users", 409)
	call(http.MethodPost, "/demo/disconnect", 200)
	state := call(http.MethodGet, "/demo/state", 200)
	if len(state["connections"].([]any)) != 0 || state["delegation_active"] != false {
		t.Fatalf("state remained after disconnect: %v", state)
	}
	call(http.MethodPost, "/demo/connect", 201)
}

func TestDemoRejectsCrossOriginMutation(t *testing.T) {
	d, err := newDemo()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.close)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/demo/connect", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://other.example")
	d.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin connect status = %d", w.Code)
	}
}
