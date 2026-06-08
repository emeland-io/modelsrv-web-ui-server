package authz

import (
	"net/http"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
)

// Config holds the authorization configuration.
type Config struct {
	// AuditorGroupID is the UUID of the Group whose members get full read access.
	AuditorGroupID string
}

// Middleware enforces authorization rules:
//   - Auditors (members of AuditorGroupID) get full access.
//   - All other authenticated users are treated as owners (filtering is applied downstream).
//   - Unauthenticated requests are rejected.
func Middleware(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := auth.FromContext(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Auditors pass through with full access.
		if isAuditor(claims, cfg.AuditorGroupID) {
			next.ServeHTTP(w, r)
			return
		}

		// Owners: allowed through; response filtering will be applied by the proxy layer.
		// TODO: Implement owner-context filtering on proxy responses.
		next.ServeHTTP(w, r)
	})
}

func isAuditor(claims *auth.Claims, auditorGroupID string) bool {
	if auditorGroupID == "" {
		return false
	}
	for _, g := range claims.Groups {
		if g == auditorGroupID {
			return true
		}
	}
	return false
}
