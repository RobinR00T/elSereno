//go:build offensive

package creds

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newChecker(t *testing.T) *ReuseChecker {
	t.Helper()
	c, err := NewReuseChecker()
	if err != nil {
		t.Fatal(err)
	}
	c.SSHTimeout = 3 * time.Second
	return c
}

func TestCheckHTTPBasicReuse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", "Basic")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if u == "svc" && p == "right" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var audited int
	c := newChecker(t)
	c.HTTPClient = srv.Client()
	c.Audit = func(_ context.Context, _, _ string, _ ReuseResult) error { audited++; return nil }
	creds := []Credential{{User: "svc", Pass: "wrong", Source: "s"}, {User: "svc", Pass: "right", Source: "s"}}
	rep, err := c.CheckHTTPBasic(context.Background(), srv.URL, creds)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tested != 2 || len(rep.Accepted) != 1 || rep.Accepted[0].User != "svc" {
		t.Fatalf("report %+v", rep)
	}
	if rep.Accepted[0].Fingerprint == "" || audited != 2 {
		t.Fatalf("fingerprint/audit: %+v audited=%d", rep.Accepted[0], audited)
	}
}

func TestCheckHTTPBasicNoGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newChecker(t)
	c.HTTPClient = srv.Client()
	rep, err := c.CheckHTTPBasic(context.Background(), srv.URL, []Credential{{User: "a", Pass: "b"}})
	if err != nil || rep.Tested != 0 {
		t.Fatalf("no-gate endpoint should test nothing: %+v %v", rep, err)
	}
}

// sshTestServer starts a password-only SSH server accepting user:pass on
// a loopback listener and returns its address.
func sshTestServer(t *testing.T, user, pass string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return &ssh.Permissions{}, nil
			}
			return nil, errAuth
		},
	}
	cfg.AddHostKey(signer)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback TCP: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						_ = ch.Reject(ssh.Prohibited, "no")
					}
				}()
				_ = sc.Wait()
			}()
		}
	}()
	return ln.Addr().String()
}

var errAuth = &authErr{}

type authErr struct{}

func (*authErr) Error() string { return "permission denied" }

func TestCheckSSHReuse(t *testing.T) {
	addr := sshTestServer(t, "root", "toor")
	c := newChecker(t)
	creds := []Credential{{User: "root", Pass: "nope", Source: "ad"}, {User: "root", Pass: "toor", Source: "ad"}}
	rep, err := c.CheckSSH(context.Background(), addr, creds)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tested != 2 || len(rep.Accepted) != 1 || rep.Accepted[0].User != "root" {
		t.Fatalf("ssh report %+v", rep)
	}
	if !rep.Accepted[0].Accepted || rep.Accepted[0].Fingerprint == "" {
		t.Fatalf("accepted result %+v", rep.Accepted[0])
	}
}

func TestCheckSSHDialError(t *testing.T) {
	c := newChecker(t)
	c.SSHTimeout = 500 * time.Millisecond
	// 192.0.2.0/24 is TEST-NET-1: never routable, so this is a dial error
	// (not an auth verdict) and must surface as err.
	_, err := c.CheckSSH(context.Background(), "192.0.2.1:22", []Credential{{User: "x", Pass: "y"}})
	if err == nil {
		t.Fatal("unreachable target must error, not report accepted")
	}
}

func TestFingerprintStableWithinRun(t *testing.T) {
	c := newChecker(t)
	first, second := c.fingerprint("same"), c.fingerprint("same")
	if first != second || c.fingerprint("a") == c.fingerprint("b") {
		t.Fatal("fingerprint must be stable per password within a run and differ across passwords")
	}
}
