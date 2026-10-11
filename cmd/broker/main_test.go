package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	for _, status := range []int{200, 302, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Error("unexpected health path")
				}
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(status)
			}))
			defer s.Close()
			if err := checkHealth(s.URL + "/healthz"); (err == nil) != (status == 200) {
				t.Fatalf("status %d: %v", status, err)
			}
		})
	}
}
