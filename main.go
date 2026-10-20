package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

//go:embed web
var embedded embed.FS

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' blob: data:; "+
				"connect-src 'self'; "+
				"manifest-src 'self'; "+
				"worker-src 'self'; "+
				"base-uri 'none'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func setCacheHeader(h http.Header, name string) {
	switch {
	case name == "index.html" || name == "sw.js" || name == "manifest.json":
		h.Set("Cache-Control", "no-cache")
	case strings.HasPrefix(name, "icons/"):
		h.Set("Cache-Control", "public, max-age=604800, immutable")
	default:
		h.Set("Cache-Control", "public, max-age=3600")
	}
}

func spaHandler(webFS fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(webFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || name == "." || name == "index.html" {
			serveIndex(w, webFS)
			return
		}
		if f, err := webFS.Open(name); err == nil {
			f.Close()
			setCacheHeader(w.Header(), name)
			fileServer.ServeHTTP(w, r)
			return
		}
		if !strings.Contains(path.Base(name), ".") {
			serveIndex(w, webFS)
			return
		}
		http.NotFound(w, r)
	})
}

func serveIndex(w http.ResponseWriter, webFS fs.FS) {
	data, err := fs.ReadFile(webFS, "index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	setCacheHeader(w.Header(), "index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok"))
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{
		"version":   version,
		"commit":    commit,
		"buildDate": buildDate,
		"go":        runtime.Version(),
	})
}

func handler() http.Handler {
	webFS, err := fs.Sub(embedded, "web")
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/version", handleVersion)
	mux.Handle("/", spaHandler(webFS))
	return securityHeaders(mux)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("CryptoPic %s (commit %s, built %s) listening on :%s", version, commit, buildDate, port)
	log.Fatal(srv.ListenAndServe())
}
