package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/config"
	"local/elsereno/internal/creds"
)

// TestBrowserGuard: what a page in the operator's browser can send to a
// loopback serve, against what the CLI and the dashboard send (PITF-092).
func TestBrowserGuard(t *testing.T) {
	const self = "127.0.0.1:8787"
	cases := []struct {
		name                 string
		loopback             bool
		method, host, origin string
		fetchSite, ctype     string
		body                 string
		unknownLength        bool
		want                 int
	}{
		// What must keep working.
		{name: "CLI JSON POST", loopback: true, method: "POST", host: self, ctype: "application/json", body: "{}", want: 200},
		{name: "CLI bodyless POST (enable)", loopback: true, method: "POST", host: self, want: 200},
		{name: "CLI DELETE", loopback: true, method: "DELETE", host: self, want: 200},
		{name: "CLI NDJSON import", loopback: true, method: "POST", host: self, ctype: "application/x-ndjson", body: "{}\n", want: 200},
		{name: "JSON with charset", loopback: true, method: "PUT", host: self, ctype: "application/json; charset=utf-8", body: "{}", want: 200},
		{name: "dashboard same-origin POST", loopback: true, method: "POST", host: self, origin: "http://" + self, fetchSite: "same-origin", ctype: "application/json", body: "{}", want: 200},
		{name: "dashboard same-origin bodyless POST", loopback: true, method: "POST", host: self, origin: "http://" + self, fetchSite: "same-origin", want: 200},
		{name: "GET via localhost", loopback: true, method: "GET", host: "localhost:8787", want: 200},
		{name: "GET via [::1]", loopback: true, method: "GET", host: "[::1]:8787", want: 200},
		{name: "cross-site GET (cannot read without CORS)", loopback: true, method: "GET", host: self, origin: "https://evil.example", fetchSite: "cross-site", want: 200},
		{name: "network bind, other Host", loopback: false, method: "GET", host: "elsereno.corp:8443", want: 200},
		{name: "cross-site OPTIONS", loopback: true, method: "OPTIONS", host: self, origin: "https://evil.example", want: 200},

		// What a hostile page could send.
		{name: "DNS rebinding GET", loopback: true, method: "GET", host: "evil.example:8787", want: http.StatusMisdirectedRequest},
		{name: "DNS rebinding POST", loopback: true, method: "POST", host: "evil.example:8787", ctype: "application/json", body: "{}", want: http.StatusMisdirectedRequest},
		{name: "cross-site JSON fetch", loopback: true, method: "POST", host: self, origin: "https://evil.example", ctype: "application/json", body: "{}", want: http.StatusForbidden},
		{name: "cross-site bodyless POST", loopback: true, method: "POST", host: self, origin: "https://evil.example", want: http.StatusForbidden},
		{name: "cross-site DELETE", loopback: true, method: "DELETE", host: self, origin: "https://evil.example", want: http.StatusForbidden},
		{name: "opaque origin", loopback: true, method: "POST", host: self, origin: "null", want: http.StatusForbidden},
		{name: "Sec-Fetch-Site cross-site, no Origin", loopback: true, method: "POST", host: self, fetchSite: "cross-site", want: http.StatusForbidden},
		{name: "Sec-Fetch-Site same-site", loopback: true, method: "POST", host: self, fetchSite: "same-site", want: http.StatusForbidden},
		{name: "text/plain body", loopback: true, method: "POST", host: self, ctype: "text/plain", body: "{}", want: http.StatusUnsupportedMediaType},
		{name: "form body", loopback: true, method: "POST", host: self, ctype: "application/x-www-form-urlencoded", body: "a=b", want: http.StatusUnsupportedMediaType},
		{name: "multipart body", loopback: true, method: "POST", host: self, ctype: "multipart/form-data; boundary=x", body: "--x--", want: http.StatusUnsupportedMediaType},
		{name: "body without Content-Type", loopback: true, method: "POST", host: self, body: "{}", want: http.StatusUnsupportedMediaType},
		{name: "network bind still checks Origin", loopback: false, method: "POST", host: "elsereno.corp:8443", origin: "https://evil.example", ctype: "application/json", body: "{}", want: http.StatusForbidden},
		{name: "empty form POST", loopback: true, method: "POST", host: self, ctype: "application/x-www-form-urlencoded", want: http.StatusUnsupportedMediaType},
		{name: "empty text/plain POST", loopback: true, method: "POST", host: self, ctype: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "<a ping> (text/ping)", loopback: true, method: "POST", host: self, ctype: "text/ping", body: "PING", want: http.StatusUnsupportedMediaType},
		{name: "CSP report", loopback: true, method: "POST", host: self, ctype: "application/csp-report", body: "{}", want: http.StatusUnsupportedMediaType},
		{name: "upper-case TEXT/PLAIN", loopback: true, method: "POST", host: self, ctype: "TEXT/PLAIN; charset=utf-8", body: "{}", want: http.StatusUnsupportedMediaType},
		{name: "streamed body of unknown length", loopback: true, method: "POST", host: self, ctype: "text/plain", body: "{}", unknownLength: true, want: http.StatusUnsupportedMediaType},
		{name: "decimal IPv4 Host", loopback: true, method: "GET", host: "2130706433:8787", want: http.StatusMisdirectedRequest},
		{name: "loopback with IPv6 zone", loopback: true, method: "GET", host: "[::1%25lo0]:8787", want: 200},
	}
	reached := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), tc.method, "http://"+tc.host+"/api/v1/scans", strings.NewReader(tc.body))
			r.Host = tc.host
			if tc.body == "" {
				r.ContentLength = 0
			}
			if tc.unknownLength {
				r.ContentLength = -1 // HTTP/2 or chunked: no length up front
			}
			for k, v := range map[string]string{"Origin": tc.origin, "Sec-Fetch-Site": tc.fetchSite, "Content-Type": tc.ctype} {
				if v != "" {
					r.Header.Set(k, v)
				}
			}
			w := httptest.NewRecorder()
			browserGuard(tc.loopback, reached).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d (%s)", w.Code, tc.want, strings.TrimSpace(w.Body.String()))
			}
		})
	}
}

// TestServer_BrowserGuardWired: the guard sits in front of the API in the
// handler NewServer builds, not only in its own unit test.
func TestServer_BrowserGuardWired(t *testing.T) {
	vault := creds.New()
	if err := vault.Init(context.Background(), []byte("browser-guard-test")); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	srv, err := NewServer(Options{Addr: "127.0.0.1:0", Web: config.Defaults().Web, Vault: vault})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/api/v1/scans", strings.NewReader(`{"input":"list:-"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain POST through the server: status %d, want 415", resp.StatusCode)
	}

	// The loopback bind pins Host: a rebinding name gets 421.
	req, err = http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.example"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("Host evil.example through the server: status %d, want 421", resp.StatusCode)
	}
}
