package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
)

func authedRequest(subject string, groups []string) *http.Request {
	req := httptest.NewRequest("GET", "/api/systems", nil)
	req.Header.Set("Authorization", "Bearer "+subject)
	if len(groups) > 0 {
		var h string
		for i, g := range groups {
			if i > 0 {
				h += ","
			}
			h += g
		}
		req.Header.Set("X-Groups", h)
	}

	// Run through auth middleware to set context
	var result *http.Request
	auth.StubMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result = r
	})).ServeHTTP(httptest.NewRecorder(), req)
	return result
}

func TestMiddleware_NoClaims(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/systems", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rec.Code)
	}
}

func TestMiddleware_AuthenticatedUser(t *testing.T) {
	var called bool
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := authedRequest("user-1", []string{"team-a"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler not called for authenticated user")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}
