package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestSPAHandler_ServesIndexFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>app</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := spaHandler(http.Dir(dir))

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{"/", http.StatusOK, "<html>app</html>"},
		{"/style.css", http.StatusOK, "body{}"},
		{"/some/route", http.StatusOK, "<html>app</html>"}, // SPA fallback
		{"/missing.js", http.StatusNotFound, ""},            // file with extension not found
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("got body %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	backend, _ := url.Parse("http://localhost:9999")
	handler := newMux(backend, "", "", testLogger())

	for _, path := range []string{"/", "/healthz"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("got %d, want 200", rec.Code)
			}
		})
	}
}

func TestProxy_ForwardsToBackend(t *testing.T) {
	// Fake modelsrv backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"systems":[]}`))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	handler := newMux(backendURL, "auditors", "", testLogger())

	req := httptest.NewRequest("GET", "/api/systems", nil)
	req.Header.Set("Authorization", "Bearer user1")
	req.Header.Set("X-Groups", "auditors")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if rec.Body.String() != `{"systems":[]}` {
		t.Errorf("got body %q, want %q", rec.Body.String(), `{"systems":[]}`)
	}
}

func TestProxy_ReturnsBADGatewayOnBackendDown(t *testing.T) {
	// Point to a backend that doesn't exist
	backendURL, _ := url.Parse("http://127.0.0.1:1") // nothing listens here
	handler := newMux(backendURL, "auditors", "", testLogger())

	req := httptest.NewRequest("GET", "/api/systems", nil)
	req.Header.Set("Authorization", "Bearer user1")
	req.Header.Set("X-Groups", "auditors")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d, want 502", rec.Code)
	}
}

func TestAPI_RejectsUnauthenticated(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:9999")
	handler := newMux(backendURL, "auditors", "", testLogger())

	req := httptest.NewRequest("GET", "/api/systems", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rec.Code)
	}
}

func TestAPI_RejectsMalformedAuth(t *testing.T) {
	backendURL, _ := url.Parse("http://localhost:9999")
	handler := newMux(backendURL, "auditors", "", testLogger())

	tests := []struct {
		name   string
		header string
	}{
		{"basic auth", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"no scheme", "just-a-token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/systems", nil)
			req.Header.Set("Authorization", tt.header)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("got %d, want 401", rec.Code)
			}
		})
	}
}

func TestAPI_AuditorGetsAccess(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	handler := newMux(backendURL, "audit-group-uuid", "", testLogger())

	req := httptest.NewRequest("GET", "/api/contexts", nil)
	req.Header.Set("Authorization", "Bearer auditor-user")
	req.Header.Set("X-Groups", "audit-group-uuid")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

func TestAPI_OwnerGetsAccess(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	handler := newMux(backendURL, "audit-group-uuid", "", testLogger())

	req := httptest.NewRequest("GET", "/api/systems", nil)
	req.Header.Set("Authorization", "Bearer owner-user")
	req.Header.Set("X-Groups", "some-other-group")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}
