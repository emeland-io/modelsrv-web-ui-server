package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MicahParks/keyfunc/v3"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
	"go.emeland.io/modelsrv-web-ui-server/internal/authz"
	"go.emeland.io/modelsrv-web-ui-server/internal/proxy"
)

func main() {
	listenAddr := flag.String("listen", envOrDefault("LISTEN_ADDR", ":8080"), "Address to listen on")
	backendURL := flag.String("backend", envOrDefault("BACKEND_URL", "http://localhost:8081"), "modelsrv backend URL")
	staticDir := flag.String("static-dir", envOrDefault("STATIC_DIR", ""), "Directory to serve static UI files from (disabled if empty)")
	auditorGroup := flag.String("auditor-group", envOrDefault("AUDITOR_GROUP_ID", ""), "UUID of the auditor Group (full access)")
	issuerURL := flag.String("issuer-url", envOrDefault("OIDC_ISSUER_URL", ""), "OIDC issuer URL (e.g. http://dex:5556/dex)")
	clientID := flag.String("client-id", envOrDefault("OIDC_CLIENT_ID", "emeland-ui"), "OIDC client ID / audience")
	noAuth := flag.Bool("no-auth", envOrDefault("NO_AUTH", "") != "", "Disable authentication (for development/demo only)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	backend, err := url.Parse(*backendURL)
	if err != nil {
		logger.Error("invalid backend URL", "error", err)
		os.Exit(1)
	}

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

	authCfg := auth.Config{IssuerURL: *issuerURL, ClientID: *clientID}
	mux := newMux(backend, *auditorGroup, *staticDir, *noAuth, authCfg, jwks, logger)

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("starting server", "listen", *listenAddr, "backend", backend.String())

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

// newMux builds the HTTP handler with proxy, auth, authz, and static file serving.
func newMux(backend *url.URL, auditorGroupID, staticDir string, noAuth bool, authCfg auth.Config, jwks keyfunc.Keyfunc, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	rp := proxy.NewSingleHostReverseProxy(backend, auditorGroupID)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("proxy error", "error", err, "path", r.URL.Path)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	var apiHandler http.Handler = rp
	if !noAuth {
		if jwks != nil {
			apiHandler = auth.JWTMiddleware(authCfg, jwks, authz.Middleware(rp))
		} else {
			apiHandler = auth.StubMiddleware(authz.Middleware(rp))
		}
	} else {
		logger.Warn("authentication disabled")
	}
	mux.Handle("/api/", apiHandler)
	mux.Handle("/swagger/", rp)
	mux.Handle("/metrics", rp)

	// Serve OIDC config for the frontend
	mux.HandleFunc("/auth/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if noAuth || authCfg.IssuerURL == "" {
			_, _ = w.Write([]byte(`{"issuerUrl":"","clientId":"","redirectUri":""}`))
		} else {
			_, _ = fmt.Fprintf(w, `{"issuerUrl":%q,"clientId":%q,"redirectUri":"http://%s/callback"}`,
				authCfg.IssuerURL, authCfg.ClientID, r.Host)
		}
	})

	// Proxy token exchange to avoid CORS issues with the OIDC provider
	if authCfg.IssuerURL != "" {
		tokenURL := authCfg.IssuerURL + "/token"
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

	if staticDir != "" {
		abs, _ := filepath.Abs(staticDir)
		logger.Info("serving static files", "dir", abs)
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
