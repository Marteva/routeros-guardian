package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })

	if got := BasicAuth(ok, "", ""); got == nil {
		t.Fatal("nil handler")
	}
	h := BasicAuth(ok, "admin", "s3cret")
	cases := []struct {
		name       string
		user, pass string
		set        bool
		want       int
	}{
		{"no credentials", "", "", false, http.StatusUnauthorized},
		{"wrong password", "admin", "nope", true, http.StatusUnauthorized},
		{"wrong user", "root", "s3cret", true, http.StatusUnauthorized},
		{"ok", "admin", "s3cret", true, http.StatusTeapot},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			if c.set {
				r.SetBasicAuth(c.user, c.pass)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("code %d, want %d", w.Code, c.want)
			}
			if c.want == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing WWW-Authenticate")
			}
		})
	}

	// Only exactly GET /healthz bypasses auth.
	for _, c := range []struct {
		method, target string
		want           int
	}{
		{http.MethodGet, "/healthz", http.StatusTeapot},
		{http.MethodGet, "/healthz?x=1", http.StatusTeapot},
		{http.MethodPost, "/healthz", http.StatusUnauthorized},
		{http.MethodHead, "/healthz", http.StatusUnauthorized},
		{http.MethodGet, "/healthz/", http.StatusUnauthorized},
		{http.MethodGet, "/healthzx", http.StatusUnauthorized},
		{http.MethodGet, "/api/healthz", http.StatusUnauthorized},
		{http.MethodGet, "/HEALTHZ", http.StatusUnauthorized},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(c.method, c.target, nil))
		if w.Code != c.want {
			t.Errorf("%s %s: code %d, want %d", c.method, c.target, w.Code, c.want)
		}
	}

	// Disabled auth passes through.
	w := httptest.NewRecorder()
	BasicAuth(ok, "", "").ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTeapot {
		t.Fatalf("disabled auth: code %d", w.Code)
	}
}
