package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey struct{}

// Claims represents the authenticated user's identity and group memberships.
type Claims struct {
	Subject string
	Groups  []string
}

// FromContext retrieves the authenticated Claims from the request context.
func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKey{}).(*Claims)
	return c
}

// Middleware validates the Authorization header and injects Claims into context.
// This is a stub: it trusts the Bearer token as a subject identifier and reads
// groups from an X-Groups header. Replace with OIDC token validation.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || token == r.Header.Get("Authorization") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		groups := parseGroups(r.Header.Get("X-Groups"))
		claims := &Claims{Subject: token, Groups: groups}
		ctx := context.WithValue(r.Context(), ctxKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func parseGroups(header string) []string {
	if header == "" {
		return nil
	}
	var groups []string
	for _, g := range strings.Split(header, ",") {
		if s := strings.TrimSpace(g); s != "" {
			groups = append(groups, s)
		}
	}
	return groups
}
