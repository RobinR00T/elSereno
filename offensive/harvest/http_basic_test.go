//go:build offensive

package harvest

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newBasicServer(user, pass string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			w.Header().Set("WWW-Authenticate", `Basic realm="router"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(string(raw), ":", 2)
		if len(parts) != 2 || parts[0] != user || parts[1] != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="router"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
}

func TestHTTPBasic_HappyPath(t *testing.T) {
	srv := newBasicServer("admin", "admin")
	t.Cleanup(srv.Close)
	target := strings.TrimPrefix(srv.URL, "http://")
	p := NewHTTPBasic()
	res, err := p.Probe(context.Background(), target, []Credential{
		{Username: "root", Password: "root"},
		{Username: "admin", Password: "admin"},
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Credential.Username != "admin" {
		t.Fatalf("wrong credential: %+v", res.Credential)
	}
}

func TestHTTPBasic_NoChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	target := strings.TrimPrefix(srv.URL, "http://")
	p := NewHTTPBasic()
	_, err := p.Probe(context.Background(), target, DefaultCredentials())
	if !errors.Is(err, ErrNoHit) {
		t.Fatalf("no challenge should be NoHit, got %v", err)
	}
}

func TestHTTPBasic_NoHit(t *testing.T) {
	srv := newBasicServer("secret-admin", "hunter2")
	t.Cleanup(srv.Close)
	target := strings.TrimPrefix(srv.URL, "http://")
	p := NewHTTPBasic()
	_, err := p.Probe(context.Background(), target, []Credential{{Username: "admin", Password: "admin"}})
	if !errors.Is(err, ErrNoHit) {
		t.Fatalf("want ErrNoHit, got %v", err)
	}
}
