package authz

import (
	"net/http"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
)

// Middleware ensures the caller is authenticated. Resource visibility is enforced
// downstream in modelsrv via trusted X-Auth-* headers injected by the proxy.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.FromContext(r.Context()) == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
