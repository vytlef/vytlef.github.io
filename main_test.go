package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer() *httptest.Server {
	return httptest.NewServer(handler())
}

func TestHealthz(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Errorf("CSP = %q", got)
	}
}

func TestVersion(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"version", "commit", "buildDate", "go"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
}

func TestIndexServed(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, "CryptoPic") {
		t.Error("index.html does not contain CryptoPic")
	}
	if !strings.Contains(body, "manifest.json") {
		t.Error("index.html does not reference manifest.json")
	}
}

func TestIndexHtmlNoRedirect(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no redirect for service worker cache)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestStaticAssets(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	cases := map[string]string{
		"/styles.css":          "text/css",
		"/js/app.js":           "text/javascript",
		"/js/crypto.js":        "text/javascript",
		"/js/stego.js":         "text/javascript",
		"/js/argon2-worker.js": "text/javascript",
		"/js/vendor/hash-wasm-argon2-4.12.0.min.js": "text/javascript",
		"/js/vendor/hash-wasm-LICENSE.txt":          "text/plain",
		"/js/memo.js":                               "text/javascript",
		"/js/theme-init.js":                         "text/javascript",
		"/manifest.json":                            "application/json",
		"/sw.js":                                    "text/javascript",
		"/icons/icon-192.png":                       "image/png",
		"/icons/icon-512.png":                       "image/png",
		"/icons/icon-maskable.png":                  "image/png",
	}
	for path, wantCT := range cases {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, wantCT) {
			t.Errorf("%s: Content-Type = %q, want prefix %q", path, ct, wantCT)
		}
		resp.Body.Close()
	}
}

func TestSpaFallback(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/halaman-tidak-ada")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 via SPA fallback", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestMissingFileIs404(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tidak-ada.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}
