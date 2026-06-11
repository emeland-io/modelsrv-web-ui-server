package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
)

// Trusted identity headers forwarded to modelsrv (must match modelsrv/pkg/authz constants).
const (
	HeaderAuthSubject = "X-Auth-Subject"
	HeaderAuthGroups  = "X-Auth-Groups"
	HeaderAuthAuditor = "X-Auth-Auditor"
)

// NewSingleHostReverseProxy returns a reverse proxy that strips client X-Auth-* headers
// and injects trusted identity headers from the authenticated claims in context.
func NewSingleHostReverseProxy(target *url.URL, auditorGroupID string) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(target)
	director := rp.Director
	rp.Director = func(req *http.Request) {
		director(req)
		stripAuthHeaders(req.Header)
		claims := auth.FromContext(req.Context())
		if claims != nil {
			req.Header.Set(HeaderAuthSubject, claims.Subject)
			if len(claims.Groups) > 0 {
				req.Header.Set(HeaderAuthGroups, strings.Join(claims.Groups, ","))
			}
			if isAuditor(claims, auditorGroupID) {
				req.Header.Set(HeaderAuthAuditor, "true")
			}
		}
	}
	return rp
}

func stripAuthHeaders(h http.Header) {
	for key := range h {
		if strings.HasPrefix(strings.ToLower(key), "x-auth-") {
			h.Del(key)
		}
	}
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
