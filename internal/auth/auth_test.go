package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_NoToken(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rec.Code)
	}
}

func TestMiddleware_ValidToken(t *testing.T) {
	var got *Claims
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer user-123")
	req.Header.Set("X-Groups", "auditors, owners")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if got == nil {
		t.Fatal("claims not set in context")
	}
	if got.Subject != "user-123" {
		t.Errorf("subject = %q, want %q", got.Subject, "user-123")
	}
	if len(got.Groups) != 2 || got.Groups[0] != "auditors" || got.Groups[1] != "owners" {
		t.Errorf("groups = %v, want [auditors owners]", got.Groups)
	}
}
