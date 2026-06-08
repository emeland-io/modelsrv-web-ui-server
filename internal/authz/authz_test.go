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
	auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result = r
	})).ServeHTTP(httptest.NewRecorder(), req)
	return result
}

func TestMiddleware_NoClaims(t *testing.T) {
	cfg := Config{AuditorGroupID: "audit-group-uuid"}
	handler := Middleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/systems", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rec.Code)
	}
}

func TestMiddleware_Auditor(t *testing.T) {
	cfg := Config{AuditorGroupID: "audit-group-uuid"}
	var called bool
	handler := Middleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := authedRequest("auditor-user", []string{"audit-group-uuid"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler not called for auditor")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

func TestMiddleware_Owner(t *testing.T) {
	cfg := Config{AuditorGroupID: "audit-group-uuid"}
	var called bool
	handler := Middleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := authedRequest("owner-user", []string{"some-other-group"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("handler not called for owner")
	}
}
