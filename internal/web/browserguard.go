package web

import (
	"mime"
	"net"
	"net/http"
	"strings"
)

// browserGuard refuses the requests that a web page open in the
// operator's browser could send to serve without the operator meaning
// to (PITF-092). In dev mode (loopback bind, no OIDC) the API has no
// authentication, so until 2026-10-17 any page could POST to
// 127.0.0.1:8787 and create scans or change schedules, and a hostile
// name resolved to 127.0.0.1 (DNS rebinding) could also read the API.
//
// It refuses:
//   - on a loopback bind, any request whose Host is not a loopback name
//     (421): a rebinding page reaches serve with its own Host;
//   - a method other than GET, HEAD and OPTIONS sent from another site:
//     a Sec-Fetch-Site other than same-origin or none, or an Origin that
//     is not this server's (403);
//   - such a method whose body or Content-Type is anything but JSON or
//     NDJSON (415): a page can send a form, multipart, text/plain,
//     text/ping or a CSP report cross-site without a CORS preflight, so
//     only the two types the API reads are accepted; a bodyless write
//     carries no Content-Type, or one of those two.
//
// The CLI and curl send no Origin and a JSON or NDJSON body, and pass.
// This is not authentication: any local process can still call the API
// in dev mode.
func browserGuard(loopbackBind bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loopbackBind && !loopbackHost(r.Host) {
			http.Error(w, "serve: Host "+r.Host+" is not a loopback name (DNS rebinding?)", http.StatusMisdirectedRequest)
			return
		}
		if safeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "serve: cross-site request refused (Sec-Fetch-Site: "+site+")", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !strings.EqualFold(origin, ownOrigin(r)) {
			http.Error(w, "serve: request from another origin refused ("+origin+")", http.StatusForbidden)
			return
		}
		if ct := r.Header.Get("Content-Type"); (hasBody(r) || ct != "") && !apiType(ct) {
			http.Error(w, "serve: send the body as application/json (or application/x-ndjson for imports)", http.StatusUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// ownOrigin is the origin a same-origin browser request to this server
// carries.
func ownOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// hasBody reports whether the request may carry a body: a positive
// length, or an unknown one (-1: chunked on HTTP/1.1, any streamed body
// on HTTP/2).
func hasBody(r *http.Request) bool {
	return r.ContentLength != 0
}

// apiType reports whether a Content-Type is one the API reads, JSON or
// NDJSON. A browser sends either cross-site only after a CORS preflight,
// which serve never answers.
func apiType(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mt == "application/json" || mt == "application/x-ndjson"
}

// loopbackHost reports whether a Host header (with or without port)
// names this machine's loopback.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i] // IPv6 zone, as in [::1%lo0]
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
