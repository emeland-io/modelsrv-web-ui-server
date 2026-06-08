package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.emeland.io/modelsrv-web-ui-server/internal/auth"
	"go.emeland.io/modelsrv-web-ui-server/internal/authz"
)

func main() {
	listenAddr := flag.String("listen", envOrDefault("LISTEN_ADDR", ":8080"), "Address to listen on")
	backendURL := flag.String("backend", envOrDefault("BACKEND_URL", "http://localhost:8081"), "modelsrv backend URL")
	staticDir := flag.String("static-dir", envOrDefault("STATIC_DIR", ""), "Directory to serve static UI files from (disabled if empty)")
	auditorGroup := flag.String("auditor-group", envOrDefault("AUDITOR_GROUP_ID", ""), "UUID of the auditor Group (full access)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	backend, err := url.Parse(*backendURL)
	if err != nil {
		logger.Error("invalid backend URL", "error", err)
		os.Exit(1)
	}

	mux := newMux(backend, *auditorGroup, *staticDir, logger)

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
func newMux(backend *url.URL, auditorGroupID, staticDir string, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("proxy error", "error", err, "path", r.URL.Path)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	authzCfg := authz.Config{AuditorGroupID: auditorGroupID}
	apiHandler := auth.Middleware(authz.Middleware(authzCfg, proxy))
	mux.Handle("/api/", apiHandler)
	mux.Handle("/swagger/", proxy)
	mux.Handle("/metrics", proxy)

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
		// Try to open the file; if it exists, serve it directly.
		if f, err := fs.Open(path); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// File not found: if path has a file extension, it's a missing asset → 404.
		if filepath.Ext(path) != "" {
			http.NotFound(w, r)
			return
		}
		// No extension → SPA route, serve index.html.
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
