package controlplane

import (
	"net/http"
	"strings"
)

// withAPIToken protects HTTP routes except /healthz when token is configured.
func withAPIToken(token string, next http.Handler) http.Handler {
	token = strings.TrimSpace(token)
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		if authorizedRequest(r, token) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func authorizedRequest(r *http.Request, token string) bool {
	if hdr := strings.TrimSpace(r.Header.Get("Authorization")); hdr != "" {
		if strings.EqualFold(hdr, "Bearer "+token) {
			return true
		}
		if hdr == token {
			return true
		}
	}
	if strings.TrimSpace(r.Header.Get("X-API-Token")) == token {
		return true
	}
	return false
}
