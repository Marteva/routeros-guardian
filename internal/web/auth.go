package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
)

// BasicAuth protects h with HTTP Basic auth. An empty user disables protection.
// Exactly "GET /healthz" is let through unauthenticated (container healthcheck);
// it reveals only ok/not-ok.
func BasicAuth(h http.Handler, user, pass string) http.Handler {
	if user == "" {
		return h
	}
	wantU := sha256.Sum256([]byte(user))
	wantP := sha256.Sum256([]byte(pass))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == healthPath {
			h.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		gotU := sha256.Sum256([]byte(u))
		gotP := sha256.Sum256([]byte(p))
		// Compare hashes so the comparison is constant-time regardless of length.
		uOK := subtle.ConstantTimeCompare(gotU[:], wantU[:]) == 1
		pOK := subtle.ConstantTimeCompare(gotP[:], wantP[:]) == 1
		if !ok || !uOK || !pOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="Guardian for RouterOS", charset="UTF-8"`)
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		h.ServeHTTP(w, r)
	})
}
