package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/MicahParks/keyfunc/v3"

	"go.emeland.io/modelsrv/pkg/authz"
	"go.emeland.io/modelsrv/pkg/backend"
	"go.emeland.io/modelsrv/pkg/endpoint"
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
	noAuth := flag.Bool("no-auth", envOrDefault("NO_AUTH", "") != "", "Disable authentication (development only)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Create in-process modelsrv backend
	b, err := backend.New()
	if err != nil {
		logger.Error("failed to create backend", "error", err)
		os.Exit(1)
	}

	// Optionally watch a data directory for YAML files
	if *dataDir != "" {
		abs, _ := filepath.Abs(*dataDir)
		logger.Info("file sensor enabled", "dir", abs)
		filesensor.Start(context.Background(), abs, b.GetModel(), nil)
	}

	// OIDC setup
	var jwks keyfunc.Keyfunc
	if !*noAuth && *issuerURL != "" {
		jwksURL := *issuerURL + "/keys"
		jwks, err = keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL})
		if err != nil {
			logger.Error("failed to fetch JWKS", "url", jwksURL, "error", err)
			os.Exit(1)
		}
		logger.Info("OIDC enabled", "issuer", *issuerURL, "clientID", *clientID)
	}

	// Build modelsrv handler
	baseURL := resolveBaseURL(*listenAddr)
	modelsrvHandler := endpoint.NewHandler(b.GetModel(), b.GetEventManager(), baseURL, endpoint.WebListenerOptions{
		TrustAuthHeaders: true,
		AuthzConfig: authz.Config{
			AuditorGroup: *auditorGroup,
			PublicTypes:  authz.ParsePublicResourceTypes(*publicTypes),
		},
	})

	// Build the top-level mux
	mux := newMux(muxConfig{
		modelsrvHandler: modelsrvHandler,
		staticDir:       *staticDir,
		noAuth:          *noAuth,
		authCfg:         auth.Config{IssuerURL: *issuerURL, ClientID: *clientID},
		jwks:            jwks,
		auditorGroupID:  *auditorGroup,
		logger:          logger,
	})

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("starting server", "listen", *listenAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("listen error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
}

type muxConfig struct {
	modelsrvHandler http.Handler
	staticDir       string
	noAuth          bool
	authCfg         auth.Config
	jwks            keyfunc.Keyfunc
	auditorGroupID  string
	logger          *slog.Logger
}

// newMux builds the HTTP handler with auth, modelsrv API, and static file serving.
func newMux(cfg muxConfig) http.Handler {
	mux := http.NewServeMux()

	// Build the header-injecting handler once; wrap with auth as needed.
	injected := headerInjector(cfg.modelsrvHandler, cfg.auditorGroupID)
	var apiHandler http.Handler
	if !cfg.noAuth {
		if cfg.jwks != nil {
			apiHandler = auth.JWTMiddleware(cfg.authCfg, cfg.jwks, injected)
		} else {
			apiHandler = auth.StubMiddleware(injected)
		}
	} else {
		cfg.logger.Warn("authentication disabled")
		apiHandler = injected
	}
	mux.Handle("/api/", apiHandler)
	mux.Handle("/swagger/", cfg.modelsrvHandler)
	mux.Handle("/metrics", cfg.modelsrvHandler)

	// OIDC config for the frontend
	mux.HandleFunc("/auth/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.noAuth || cfg.authCfg.IssuerURL == "" {
			_, _ = w.Write([]byte(`{"issuerUrl":"","clientId":"","redirectUri":""}`))
		} else {
			_, _ = fmt.Fprintf(w, `{"issuerUrl":%q,"clientId":%q,"redirectUri":"http://%s/callback"}`,
				cfg.authCfg.IssuerURL, cfg.authCfg.ClientID, r.Host)
		}
	})

	// Token exchange proxy (avoids CORS with IdP)
	if cfg.authCfg.IssuerURL != "" {
		tokenURL := cfg.authCfg.IssuerURL + "/token"
		mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			proxyReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
			resp, err := http.DefaultClient.Do(proxyReq)
			if err != nil {
				http.Error(w, "token exchange failed", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close() //nolint:errcheck
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		})
	}

	// SPA static files
	if cfg.staticDir != "" {
		abs, _ := filepath.Abs(cfg.staticDir)
		cfg.logger.Info("serving static files", "dir", abs)
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

	return mux
}

// headerInjector strips client-sent X-Auth-* headers and injects trusted identity
// headers from the authenticated claims so modelsrv's authz layer can enforce
// ownership visibility.
func headerInjector(next http.Handler, auditorGroupID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip any client-sent X-Auth-* headers to prevent spoofing.
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-auth-") {
				r.Header.Del(key)
			}
		}
		claims := auth.FromContext(r.Context())
		if claims != nil {
			r.Header.Set("X-Auth-Subject", claims.Subject)
			if len(claims.Groups) > 0 {
				r.Header.Set("X-Auth-Groups", strings.Join(claims.Groups, ","))
			}
			if auditorGroupID != "" {
				for _, g := range claims.Groups {
					if g == auditorGroupID {
						r.Header.Set("X-Auth-Auditor", "true")
						break
					}
				}
			}
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
