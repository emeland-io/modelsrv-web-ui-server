package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"go.emeland.io/modelsrv/pkg/authz"
	"go.emeland.io/modelsrv/pkg/backend"
	"go.emeland.io/modelsrv/pkg/endpoint"
	"go.emeland.io/modelsrv/pkg/events"
	"go.emeland.io/modelsrv/pkg/filesensor"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
)

func main() {
	listenAddr := flag.String("listen", envOrDefault("LISTEN_ADDR", ":8080"), "Address to listen on")
	dataDir := flag.String("data-dir", envOrDefault("DATA_DIR", ""), "Directory to watch for YAML model definitions (disabled if empty)")
	staticDir := flag.String("static-dir", envOrDefault("STATIC_DIR", ""), "Directory to serve static UI files from (disabled if empty)")
	auditorGroup := flag.String("auditor-group", envOrDefault("AUDITOR_GROUP_ID", ""), "UUID of the auditor group (full access)")
	publicTypes := flag.String("public-resource-types", envOrDefault("PUBLIC_RESOURCE_TYPES", ""), "Comma-separated resource types always visible")
	issuerURL := flag.String("issuer-url", envOrDefault("OIDC_ISSUER_URL", ""), "OIDC issuer URL")
	clientID := flag.String("client-id", envOrDefault("OIDC_CLIENT_ID", "emeland-ui"), "OIDC client ID / audience")
	redirectURIScheme := flag.String("redirect-uri-scheme", envOrDefault("REDIRECT_URI_SCHEME", "http"), "URI scheme for redirect URI (http or https)")
	noAuthDefault, err := parseEnvBool("NO_AUTH", false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	noAuth := flag.Bool("no-auth", noAuthDefault, "Disable authentication (development only)")
	logLevel := flag.String("log-level", envOrDefault("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	logEncoding := flag.String("log-encoding", envOrDefault("LOG_ENCODING", "json"), "Log encoding (json or console)")
	flag.Parse()

	zapLog, err := newLogger(*logLevel, *logEncoding)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer zapLog.Sync() //nolint:errcheck

	// modelsrv writes some internal diagnostics via the std log package; route
	// them through zap so all output shares one format.
	defer zap.RedirectStdLog(zapLog)()

	logger := zapLog.Sugar()

	// Validate redirectURIScheme
	if err := validateRedirectURIScheme(*redirectURIScheme); err != nil {
		logger.Errorw("invalid redirect-uri-scheme", "error", err)
		os.Exit(1)
	}

	// Create in-process modelsrv backend
	b, err := backend.New(backend.WithLogger(logger))
	if err != nil {
		logger.Errorw("failed to create backend", "error", err)
		os.Exit(1)
	}

	// Optionally watch a data directory for YAML files
	if *dataDir != "" {
		abs, _ := filepath.Abs(*dataDir)
		logger.Infow("file sensor enabled", "dir", abs)
		filesensor.Start(context.Background(), abs, b.GetModel(), logger)
	}

	// OIDC setup
	var jwks keyfunc.Keyfunc
	if !*noAuth && *issuerURL != "" {
		jwksURL := *issuerURL + "/keys"
		jwks, err = keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL})
		if err != nil {
			logger.Errorw("failed to fetch JWKS", "url", jwksURL, "error", err)
			os.Exit(1)
		}
		logger.Infow("OIDC enabled", "issuer", *issuerURL, "clientID", *clientID)
	}

	// Build modelsrv handler
	baseURL := resolveBaseURL(*listenAddr)
	modelsrvHandler := endpoint.NewHandler(b.GetModel(), b.GetEventManager(), baseURL, endpoint.WebListenerOptions{
		TrustAuthHeaders: true,
		Logger:           logger,
		AuthzConfig: authz.Config{
			AuditorGroup: *auditorGroup,
			PublicTypes:  authz.ParsePublicResourceTypes(*publicTypes),
		},
	})

	public := authz.ParsePublicResourceTypes(*publicTypes)
	authMode := "jwt"
	switch {
	case *noAuth:
		authMode = "disabled"
	case *issuerURL == "":
		authMode = "stub"
	}
	logger.Infow("server config",
		"listen", *listenAddr,
		"baseURL", baseURL,
		"auth", authMode,
		"eventsPushAuth", "bypassed",
		"issuer", *issuerURL,
		"clientID", *clientID,
		"redirectURIScheme", *redirectURIScheme,
		"auditorGroup", *auditorGroup,
		"publicResourceTypes", *publicTypes,
		"publicResourceTypesResolved", resourceTypeNames(public),
		"publicResourceTypesUnrecognized", unrecognizedPublicTypes(*publicTypes),
		"dataDir", *dataDir,
		"staticDir", *staticDir,
		"logLevel", *logLevel,
		"logEncoding", *logEncoding,
	)

	// Build the top-level mux
	mux := newMux(muxConfig{
		modelsrvHandler:   modelsrvHandler,
		staticDir:         *staticDir,
		noAuth:            *noAuth,
		authCfg:           auth.Config{IssuerURL: *issuerURL, ClientID: *clientID, RedirectURIScheme: *redirectURIScheme, Logger: logger},
		jwks:              jwks,
		auditorGroupID:    *auditorGroup,
		logger:            logger,
	})

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Infow("starting server", "listen", *listenAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorw("listen error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Infow("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Errorw("shutdown error", "error", err)
	}
}

// newLogger builds the application logger. Defaults match the previous slog
// setup (JSON on stdout at info level) so log consumers keep working.
func newLogger(level, encoding string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.DisableStacktrace = true
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	if level != "" {
		var l zap.AtomicLevel
		if err := l.UnmarshalText([]byte(level)); err != nil {
			return nil, fmt.Errorf("invalid log-level %q: must be debug, info, warn or error", level)
		}
		cfg.Level = l
	}

	switch encoding {
	case "", "json":
		cfg.Encoding = "json"
	case "console":
		cfg.Encoding = "console"
	default:
		return nil, fmt.Errorf("invalid log-encoding %q: must be json or console", encoding)
	}

	return cfg.Build()
}

type muxConfig struct {
	modelsrvHandler http.Handler
	staticDir       string
	noAuth          bool
	authCfg         auth.Config
	jwks            keyfunc.Keyfunc
	auditorGroupID  string
	logger          *zap.SugaredLogger
}

// newMux builds the HTTP handler with auth, modelsrv API, and static file serving.
func newMux(cfg muxConfig) http.Handler {
	if cfg.authCfg.Logger == nil {
		cfg.authCfg.Logger = cfg.logger
	}
	mux := http.NewServeMux()

	// Build the header-injecting handler once; wrap with auth as needed.
	injected := headerInjector(cfg.logger, cfg.modelsrvHandler, cfg.auditorGroupID)
	var apiHandler http.Handler
	if !cfg.noAuth {
		if cfg.jwks != nil {
			apiHandler = auth.JWTMiddleware(cfg.authCfg, cfg.jwks, injected)
			cfg.logger.Debugw("api auth wrapper", "mode", "jwt", "issuer", cfg.authCfg.IssuerURL, "clientID", cfg.authCfg.ClientID, "eventsPush", "bypassed")
		} else {
			apiHandler = auth.StubMiddleware(injected)
			cfg.logger.Debugw("api auth wrapper", "mode", "stub", "reason", "issuer url empty", "eventsPush", "bypassed")
		}
	} else {
		cfg.logger.Warnw("authentication disabled")
		cfg.logger.Debugw("api auth wrapper", "mode", "disabled", "eventsPush", "bypassed")
		apiHandler = injected
	}
	// In-cluster replication (filter/sensors) must not require a browser Dex JWT.
	// More-specific method+path patterns take precedence over the /api/ prefix.
	mux.Handle("POST /api/events/push", injected)
	mux.Handle("/api/", apiHandler)
	mux.Handle("/swagger/", cfg.modelsrvHandler)
	mux.Handle("/metrics", cfg.modelsrvHandler)

	// OIDC config for the frontend
	mux.HandleFunc("/auth/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.noAuth || cfg.authCfg.IssuerURL == "" {
			_, _ = w.Write([]byte(`{"issuerUrl":"","clientId":"","redirectUri":""}`))
		} else {
			scheme := cfg.authCfg.RedirectURIScheme
			if scheme == "" {
				scheme = "http"
			}
			issuer := publicIssuerURL(cfg.authCfg.IssuerURL, r.Host)
			cfg.logger.Debugw("auth config", "requestHost", r.Host, "configuredIssuer", cfg.authCfg.IssuerURL, "publicIssuer", issuer, "scheme", scheme, "clientID", cfg.authCfg.ClientID)
			_, _ = fmt.Fprintf(w, `{"issuerUrl":%q,"clientId":%q,"redirectUri":"%s://%s/callback"}`,
				issuer, cfg.authCfg.ClientID, scheme, r.Host)
		}
	})

	// Token exchange proxy (avoids CORS with IdP). Always registered so POST
	// /auth/token is never swallowed by the SPA fallback (which would return 200 HTML).
	mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cfg.authCfg.IssuerURL == "" {
			cfg.logger.Warnw("token exchange skipped", "reason", "OIDC issuer not configured")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"token_proxy_unconfigured","error_description":"OIDC issuer is not configured"}`))
			return
		}

		tokenURL := cfg.authCfg.IssuerURL + "/token"
		cfg.logger.Debugw("token exchange upstream", "url", tokenURL, "contentType", r.Header.Get("Content-Type"), "contentLength", r.ContentLength, "remote", r.RemoteAddr)
		proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, r.Body)
		if err != nil {
			cfg.logger.Errorw("token exchange bad request", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		proxyReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		resp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			cfg.logger.Errorw("token exchange failed", "upstream", tokenURL, "error", err)
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			cfg.logger.Warnw("token exchange rejected", "upstream", tokenURL, "status", resp.StatusCode, "error", truncateForLog(respBody, 500))
		} else {
			cfg.logger.Infow("token exchange", "upstream", tokenURL, "status", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	})

	// SPA static files
	if cfg.staticDir != "" {
		abs, _ := filepath.Abs(cfg.staticDir)
		cfg.logger.Infow("serving static files", "dir", abs)
		mux.Handle("/", spaHandler(http.Dir(abs)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" || r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintln(w, "ok")
				return
			}
			http.NotFound(w, r)
		})
	}

	return accessLog(cfg.logger, mux)
}

// headerInjector strips client-sent X-Auth-* headers and injects trusted identity
// headers from the authenticated claims so modelsrv's authz layer can enforce
// ownership visibility.
func headerInjector(log *zap.SugaredLogger, next http.Handler, auditorGroupID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip any client-sent X-Auth-* headers to prevent spoofing.
		var stripped []string
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-auth-") {
				stripped = append(stripped, key)
				r.Header.Del(key)
			}
		}
		claims := auth.FromContext(r.Context())
		auditor := false
		if claims != nil {
			r.Header.Set("X-Auth-Subject", claims.Subject)
			if len(claims.Groups) > 0 {
				r.Header.Set("X-Auth-Groups", strings.Join(claims.Groups, ","))
			}
			if auditorGroupID != "" {
				for _, g := range claims.Groups {
					if g == auditorGroupID {
						r.Header.Set("X-Auth-Auditor", "true")
						auditor = true
						break
					}
				}
			}
		}
		if log != nil {
			subject := ""
			groups := 0
			if claims != nil {
				subject = claims.Subject
				groups = len(claims.Groups)
			}
			log.Infow("auth headers",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
				"authenticated", claims != nil,
				"subject", subject,
				"groups", groups,
				"auditor", auditor,
				"strippedClientHeaders", stripped,
			)
			log.Debugw("auth headers detail",
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"proto", r.Proto,
				"groupNames", func() []string {
					if claims == nil {
						return nil
					}
					return claims.Groups
				}(),
				"auditorGroupConfigured", auditorGroupID != "",
				"forwardedHeaders", map[string]string{
					"X-Auth-Subject": r.Header.Get("X-Auth-Subject"),
					"X-Auth-Groups":  r.Header.Get("X-Auth-Groups"),
					"X-Auth-Auditor": r.Header.Get("X-Auth-Auditor"),
				},
				"requestHeaders", redactHeaders(r.Header),
			)
		}
		next.ServeHTTP(w, r)
	})
}

// resolveBaseURL produces a usable base URL for modelsrv's OpenAPI spec links.
// When listening on all interfaces (e.g. ":8080"), it substitutes localhost.
func resolveBaseURL(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Sprintf("http://%s/api", listenAddr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s/api", net.JoinHostPort(host, port))
}

// spaHandler serves static files, falling back to index.html for SPA routing.
func spaHandler(fs http.FileSystem) http.Handler {
	fileServer := http.FileServer(fs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if f, err := fs.Open(path); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		if filepath.Ext(path) != "" {
			http.NotFound(w, r)
			return
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

func envOrDefault(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// parseEnvBool reads key from the environment. Unset or empty uses fallback.
// Values are parsed with strconv.ParseBool (true/false, 1/0, t/f, TRUE/FALSE).
func parseEnvBool(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s %q: must be a boolean (true/false, 1/0)", key, v)
	}
	return b, nil
}

// validateRedirectURIScheme checks that the scheme is one of the allowed values.
func validateRedirectURIScheme(scheme string) error {
	switch scheme {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("must be 'http' or 'https', got %q", scheme)
	}
}

// accessLog records every request. /api and /auth log at info (warn on 4xx/5xx);
// everything else logs at debug. POST /api/events/push also logs the payload,
// because that is the replication hop from the filter and a rejection here is
// otherwise only visible upstream.
func accessLog(log *zap.SugaredLogger, next http.Handler) http.Handler {
	if log == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		push := r.Method == http.MethodPost && r.URL.Path == "/api/events/push"
		var reqBody []byte
		if push && r.Body != nil {
			var err error
			reqBody, err = io.ReadAll(r.Body)
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
			fields := []any{
				"remote", r.RemoteAddr,
				"host", r.Host,
				"userAgent", r.UserAgent(),
				"contentType", r.Header.Get("Content-Type"),
				"contentLength", r.ContentLength,
				"bytes", len(reqBody),
				"hasAuth", r.Header.Get("Authorization") != "",
				"forwardedFor", r.Header.Get("X-Forwarded-For"),
			}
			if err != nil {
				fields = append(fields, "bodyError", err)
			}
			for k, v := range summarizePush(reqBody) {
				fields = append(fields, k, v)
			}
			fields = append(fields, "body", truncateForLog(reqBody, 4000))
			log.Infow("events push received", fields...)
		}

		log.Debugw("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
			"proto", r.Proto,
			"remote", r.RemoteAddr,
			"host", r.Host,
			"userAgent", r.UserAgent(),
			"contentType", r.Header.Get("Content-Type"),
			"contentLength", r.ContentLength,
			"transferEncoding", r.TransferEncoding,
			"hasAuth", r.Header.Get("Authorization") != "",
			"eventsPush", push,
			"headers", redactHeaders(r.Header),
		)

		sw := &captureWriter{ResponseWriter: w, status: http.StatusOK, limit: 4000}
		next.ServeHTTP(sw, r)

		path := r.URL.Path
		fields := []any{
			"method", r.Method,
			"path", r.URL.RequestURI(),
			"status", sw.status,
			"bytes", sw.n,
			"duration", time.Since(start).String(),
			"remote", r.RemoteAddr,
			"host", r.Host,
			"userAgent", r.UserAgent(),
			"hasAuth", r.Header.Get("Authorization") != "",
			"contentType", r.Header.Get("Content-Type"),
			"contentLength", r.ContentLength,
		}
		if push || sw.status >= 400 {
			fields = append(fields, "response", truncateForLog(sw.buf.Bytes(), 4000))
		}
		log.Debugw("http response",
			"method", r.Method,
			"path", path,
			"status", sw.status,
			"bytes", sw.n,
			"duration", time.Since(start).String(),
			"headers", redactHeaders(sw.Header()),
			"body", truncateForLog(sw.buf.Bytes(), 4000),
		)

		interesting := strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/auth/")
		switch {
		case sw.status >= 500:
			log.Errorw("http", fields...)
		case sw.status >= 400:
			log.Warnw("http", fields...)
		case interesting || push:
			log.Infow("http", fields...)
		default:
			log.Debugw("http", fields...)
		}
	})
}

type captureWriter struct {
	http.ResponseWriter
	status int
	n      int
	buf    bytes.Buffer
	limit  int
}

func (w *captureWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureWriter) Write(b []byte) (int, error) {
	if w.buf.Len() < w.limit {
		remain := w.limit - w.buf.Len()
		if len(b) > remain {
			_, _ = w.buf.Write(b[:remain])
		} else {
			_, _ = w.buf.Write(b)
		}
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += n
	return n, err
}

func summarizePush(body []byte) map[string]any {
	out := map[string]any{}
	if len(bytes.TrimSpace(body)) == 0 {
		out["parseError"] = "empty body"
		return out
	}
	var ev struct {
		Kind       string         `json:"kind"`
		Operation  any            `json:"operation"`
		ResourceID string         `json:"resourceId"`
		Resource   map[string]any `json:"resource"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		out["parseError"] = err.Error()
		return out
	}
	out["kind"] = ev.Kind
	out["operation"] = ev.Operation
	if ev.ResourceID != "" {
		out["resourceId"] = ev.ResourceID
	}
	if ev.Resource == nil {
		return out
	}
	out["resourceKeys"] = mapKeys(ev.Resource)
	for _, k := range []string{
		"displayName", "resourceType", "findingId", "findingTypeId",
		"apiInstanceId", "systemId", "systemInstanceId", "nodeId",
		"componentId", "componentInstanceId", "contextId",
	} {
		if v, ok := ev.Resource[k]; ok {
			out[k] = v
		}
	}
	return out
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func resourceTypeNames(types map[events.ResourceType]bool) []string {
	names := make([]string, 0, len(types))
	for rt := range types {
		names = append(names, rt.String())
	}
	return names
}

func unrecognizedPublicTypes(raw string) []string {
	var unknown []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if events.ParseResourceType(part) == events.UnknownResourceType {
			unknown = append(unknown, part)
		}
	}
	return unknown
}

func redactHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		v := strings.Join(vals, ",")
		switch strings.ToLower(k) {
		case "authorization", "cookie", "set-cookie", "x-api-key":
			v = fmt.Sprintf("redacted len=%d", len(v))
		}
		out[k] = v
	}
	return out
}

func truncateForLog(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// publicIssuerURL rewrites a loopback IdP host (localhost ↔ 127.0.0.1) to match
// the host the browser used for the UI. Token proxy and JWKS keep the original
// issuer; only /auth/config.json needs a URL the browser can open.
func publicIssuerURL(issuer, requestHost string) string {
	uiHost, _, err := net.SplitHostPort(requestHost)
	if err != nil {
		uiHost = requestHost
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return issuer
	}
	idpHost, idpPort, err := net.SplitHostPort(u.Host)
	if err != nil {
		idpHost, idpPort = u.Host, ""
	}
	if !isLoopbackHost(uiHost) || !isLoopbackHost(idpHost) || uiHost == idpHost {
		return issuer
	}
	if idpPort != "" {
		u.Host = net.JoinHostPort(uiHost, idpPort)
	} else {
		u.Host = uiHost
	}
	return u.String()
}

func isLoopbackHost(host string) bool {
	h := strings.Trim(host, "[]")
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
