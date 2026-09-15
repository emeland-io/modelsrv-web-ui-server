package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
)

func testLogger() *zap.SugaredLogger {
	return zap.NewNop().Sugar()
}

// fakeModelsrvHandler captures the headers it receives.
func fakeModelsrvHandler(captured *http.Header) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if captured != nil {
			*captured = r.Header.Clone()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func testMux(opts ...func(*muxConfig)) http.Handler {
	cfg := muxConfig{
		modelsrvHandler: fakeModelsrvHandler(nil),
		noAuth:          true,
		logger:          testLogger(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	return newMux(cfg)
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
		{"/some/route", http.StatusOK, "<html>app</html>"},
		{"/missing.js", http.StatusNotFound, ""},
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
	handler := testMux()

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

func TestAPI_RejectsUnauthenticated(t *testing.T) {
	handler := testMux(func(c *muxConfig) { c.noAuth = false })

	req := httptest.NewRequest("GET", "/api/systems", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rec.Code)
	}
}

func TestAPI_StubAuth_InjectsHeaders(t *testing.T) {
	const auditorGroup = "audit-group-uuid"
	var captured http.Header

	handler := testMux(func(c *muxConfig) {
		c.modelsrvHandler = fakeModelsrvHandler(&captured)
		c.noAuth = false
		c.auditorGroupID = auditorGroup
	})

	req := httptest.NewRequest("GET", "/api/systems", nil)
	req.Header.Set("Authorization", "Bearer user-1")
	req.Header.Set("X-Groups", "team-a,"+auditorGroup)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if captured.Get("X-Auth-Subject") != "user-1" {
		t.Errorf("X-Auth-Subject = %q, want %q", captured.Get("X-Auth-Subject"), "user-1")
	}
	if captured.Get("X-Auth-Groups") != "team-a,"+auditorGroup {
		t.Errorf("X-Auth-Groups = %q, want %q", captured.Get("X-Auth-Groups"), "team-a,"+auditorGroup)
	}
	if captured.Get("X-Auth-Auditor") != "true" {
		t.Errorf("X-Auth-Auditor = %q, want %q", captured.Get("X-Auth-Auditor"), "true")
	}
}

func TestAPI_NoAuth_PassesThrough(t *testing.T) {
	handler := testMux()

	req := httptest.NewRequest("GET", "/api/systems", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

func TestHeaderInjector_StripsClientSpoofedHeaders(t *testing.T) {
	const auditorGroup = "audit-group-uuid"
	var captured http.Header

	inner := headerInjector(fakeModelsrvHandler(&captured), auditorGroup)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Auth-Subject", "spoofed")
	req.Header.Set("X-Auth-Auditor", "true")

	// Inject real claims via auth.NewContext
	claims := &auth.Claims{Subject: "real-user", Groups: []string{"team-b"}}
	req = req.WithContext(auth.NewContext(req.Context(), claims))

	rec := httptest.NewRecorder()
	inner.ServeHTTP(rec, req)

	if captured.Get("X-Auth-Subject") != "real-user" {
		t.Errorf("X-Auth-Subject = %q, want %q", captured.Get("X-Auth-Subject"), "real-user")
	}
	if captured.Get("X-Auth-Auditor") != "" {
		t.Errorf("X-Auth-Auditor should be empty for non-auditor, got %q", captured.Get("X-Auth-Auditor"))
	}
}

func TestResolveBaseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{":8080", "http://localhost:8080/api"},
		{"0.0.0.0:8080", "http://localhost:8080/api"},
		{"[::]:8080", "http://localhost:8080/api"},
		{"127.0.0.1:9000", "http://127.0.0.1:9000/api"},
		{"myhost:443", "http://myhost:443/api"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := resolveBaseURL(tt.input)
			if got != tt.want {
				t.Errorf("resolveBaseURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAuthConfigJSON_NoAuth(t *testing.T) {
	handler := testMux()

	req := httptest.NewRequest("GET", "/auth/config.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), `"issuerUrl":""`) {
		t.Errorf("expected empty issuerUrl, got %q", rec.Body.String())
	}
}

func TestAuthConfigJSON_WithIssuer(t *testing.T) {
	handler := testMux(func(c *muxConfig) {
		c.noAuth = false
		c.authCfg = auth.Config{IssuerURL: "http://dex:5556/dex", ClientID: "my-client"}
	})

	req := httptest.NewRequest("GET", "/auth/config.json", nil)
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"issuerUrl":"http://dex:5556/dex"`) {
		t.Errorf("missing issuerUrl in %q", body)
	}
	if !strings.Contains(body, `"clientId":"my-client"`) {
		t.Errorf("missing clientId in %q", body)
	}
	if !strings.Contains(body, `"redirectUri":"http://localhost:8080/callback"`) {
		t.Errorf("missing redirectUri in %q", body)
	}
}

func TestAuthConfigJSON_RewritesLoopbackIssuerToMatchUIHost(t *testing.T) {
	handler := testMux(func(c *muxConfig) {
		c.noAuth = false
		c.authCfg = auth.Config{IssuerURL: "http://localhost:5556/dex", ClientID: "emeland-ui"}
	})

	req := httptest.NewRequest("GET", "/auth/config.json", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `"issuerUrl":"http://127.0.0.1:5556/dex"`) {
		t.Errorf("expected issuer rewritten to 127.0.0.1, got %q", body)
	}
	if !strings.Contains(body, `"redirectUri":"http://127.0.0.1:8080/callback"`) {
		t.Errorf("expected matching redirectUri, got %q", body)
	}
}

func TestPublicIssuerURL(t *testing.T) {
	tests := []struct {
		issuer, host, want string
	}{
		{"http://localhost:5556/dex", "127.0.0.1:8080", "http://127.0.0.1:5556/dex"},
		{"http://127.0.0.1:5556/dex", "localhost:8080", "http://localhost:5556/dex"},
		{"http://localhost:5556/dex", "localhost:8080", "http://localhost:5556/dex"},
		{"http://dex.example.com/dex", "127.0.0.1:8080", "http://dex.example.com/dex"},
		{"http://localhost:5556/dex", "emeland.example.com", "http://localhost:5556/dex"},
	}
	for _, tt := range tests {
		if got := publicIssuerURL(tt.issuer, tt.host); got != tt.want {
			t.Errorf("publicIssuerURL(%q, %q) = %q, want %q", tt.issuer, tt.host, got, tt.want)
		}
	}
}

func TestAuthToken_MethodNotAllowed(t *testing.T) {
	handler := testMux(func(c *muxConfig) {
		c.authCfg = auth.Config{IssuerURL: "http://dex:5556/dex", ClientID: "x"}
	})

	req := httptest.NewRequest("GET", "/auth/token", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d, want 405", rec.Code)
	}
}

func TestAuthToken_ProxiesToIdP(t *testing.T) {
	// Fake IdP token endpoint
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok"}`))
	}))
	defer idp.Close()

	handler := testMux(func(c *muxConfig) {
		// Point issuer to fake IdP (token endpoint = issuerURL + "/token")
		c.authCfg = auth.Config{IssuerURL: idp.URL, ClientID: "x"}
	})

	req := httptest.NewRequest("POST", "/auth/token", strings.NewReader("grant_type=authorization_code&code=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "access_token") {
		t.Errorf("expected token response, got %q", rec.Body.String())
	}
}

func TestAuthToken_ForwardsIdPErrorAndLogs(t *testing.T) {
	core, observed := observer.New(zap.WarnLevel)
	logger := zap.New(core).Sugar()

	var gotPath, gotBody string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"fake dex"}`))
	}))
	defer idp.Close()

	handler := testMux(func(c *muxConfig) {
		c.noAuth = false
		c.logger = logger
		c.authCfg = auth.Config{IssuerURL: idp.URL, ClientID: "emeland-ui", RedirectURIScheme: "http"}
	})

	form := "grant_type=authorization_code&client_id=emeland-ui&code=abc&redirect_uri=http://localhost:8080/callback&code_verifier=verifier"
	req := httptest.NewRequest("POST", "/auth/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_request"`) {
		t.Errorf("expected Dex error body, got %q", rec.Body.String())
	}
	if gotPath != "/token" {
		t.Errorf("upstream path = %q, want /token", gotPath)
	}
	if !strings.Contains(gotBody, "grant_type=authorization_code") || !strings.Contains(gotBody, "code_verifier=verifier") {
		t.Errorf("upstream did not receive form body: %q", gotBody)
	}
	if observed.FilterMessage("token exchange rejected").Len() == 0 {
		t.Fatalf("expected warn log for rejected token exchange, got %#v", observed.All())
	}
}

func TestAuthToken_UnconfiguredDoesNotServeSPA(t *testing.T) {
	core, observed := observer.New(zap.WarnLevel)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>app</html>"), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := testMux(func(c *muxConfig) {
		c.staticDir = dir
		c.logger = zap.New(core).Sugar()
	})

	req := httptest.NewRequest("POST", "/auth/token", strings.NewReader("grant_type=authorization_code&code=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rec.Header().Get("Content-Type"))
	}
	if strings.Contains(rec.Body.String(), "<html>") {
		t.Errorf("SPA fallback must not handle /auth/token, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "token_proxy_unconfigured") {
		t.Errorf("expected unconfigured error, got %q", rec.Body.String())
	}
	if observed.FilterMessage("token exchange skipped").Len() == 0 {
		t.Fatalf("expected warn log when issuer is missing, got %#v", observed.All())
	}
}

func TestAuthConfigJSON_WithHTTPSScheme(t *testing.T) {
	handler := testMux(func(c *muxConfig) {
		c.noAuth = false
		c.authCfg = auth.Config{
			IssuerURL:         "https://dex.example.com/dex",
			ClientID:          "my-client",
			RedirectURIScheme: "https",
		}
	})

	req := httptest.NewRequest("GET", "/auth/config.json", nil)
	req.Host = "api.example.com:443"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"redirectUri":"https://api.example.com:443/callback"`) {
		t.Errorf("expected https redirectUri, got %q", body)
	}
}

func TestAuthConfigJSON_WithHTTPScheme(t *testing.T) {
	handler := testMux(func(c *muxConfig) {
		c.noAuth = false
		c.authCfg = auth.Config{
			IssuerURL:         "http://dex:5556/dex",
			ClientID:          "my-client",
			RedirectURIScheme: "http",
		}
	})

	req := httptest.NewRequest("GET", "/auth/config.json", nil)
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"redirectUri":"http://localhost:8080/callback"`) {
		t.Errorf("expected http redirectUri, got %q", body)
	}
}

func TestAuthConfigJSON_DefaultSchemeIsHTTP(t *testing.T) {
	handler := testMux(func(c *muxConfig) {
		c.noAuth = false
		// Explicitly use empty scheme to test default behavior
		c.authCfg = auth.Config{
			IssuerURL:         "http://dex:5556/dex",
			ClientID:          "my-client",
			RedirectURIScheme: "",
		}
	})

	req := httptest.NewRequest("GET", "/auth/config.json", nil)
	req.Host = "example.com:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"redirectUri":"http://example.com:8080/callback"`) {
		t.Errorf("expected http redirectUri as default, got %q", body)
	}
}

func TestValidateRedirectURIScheme(t *testing.T) {
	tests := []struct {
		scheme    string
		wantValid bool
	}{
		{"http", true},
		{"https", true},
		{"HTTP", false},
		{"HTTPS", false},
		{"ftp", false},
		{"", false},
		{"ws", false},
		{"wss", false},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			err := validateRedirectURIScheme(tt.scheme)
			if (err == nil) != tt.wantValid {
				t.Errorf("validateRedirectURIScheme(%q) error = %v, want valid = %v", tt.scheme, err, tt.wantValid)
			}
			if err != nil && !strings.Contains(err.Error(), "must be 'http' or 'https'") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name      string
		level     string
		encoding  string
		wantValid bool
	}{
		{"defaults", "", "", true},
		{"json info", "info", "json", true},
		{"console debug", "debug", "console", true},
		{"warn", "warn", "json", true},
		{"error", "error", "json", true},
		{"bad level", "verbose", "json", false},
		{"bad encoding", "info", "xml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := newLogger(tt.level, tt.encoding)
			if (err == nil) != tt.wantValid {
				t.Fatalf("newLogger(%q, %q) error = %v, want valid = %v", tt.level, tt.encoding, err, tt.wantValid)
			}
			if tt.wantValid && log == nil {
				t.Error("expected a logger, got nil")
			}
		})
	}
}

