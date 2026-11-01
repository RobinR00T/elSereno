//go:build offensive

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"local/elsereno/offensive/creds"
)

func getWithContext(t *testing.T, c *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Do(req)
}

func TestCheckReuseTLSPosture(t *testing.T) {
	validPin := strings.Repeat("ab", sha256.Size) // 64 hex chars
	cases := []struct {
		name    string
		o       reuseOpts
		wantErr bool
	}{
		{"http no pin no ack", reuseOpts{protocol: creds.ProtoHTTPBasic}, true},
		{"http insecure ack", reuseOpts{protocol: creds.ProtoHTTPBasic, insecureTLS: true}, false},
		{"http valid pin", reuseOpts{protocol: creds.ProtoHTTPBasic, tlsPin: validPin}, false},
		{"http bad pin", reuseOpts{protocol: creds.ProtoHTTPBasic, tlsPin: "xyz"}, true},
		{"ssh no ack", reuseOpts{protocol: creds.ProtoSSH}, true},
		{"ssh insecure ack", reuseOpts{protocol: creds.ProtoSSH, insecureTLS: true}, false},
		{"ssh with pin rejected", reuseOpts{protocol: creds.ProtoSSH, tlsPin: validPin}, true},
	}
	for _, c := range cases {
		err := checkReuseTLSPosture(c.o)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestDeviceClientPinning(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	leaf := ts.Certificate()
	sum := sha256.Sum256(leaf.Raw)
	goodPin := hex.EncodeToString(sum[:])

	// Correct pin: the request completes (self-signed cert accepted via pin).
	okClient := deviceClient(5*time.Second, "", goodPin)
	resp, err := getWithContext(t, okClient, ts.URL)
	if err != nil {
		t.Fatalf("pinned client should connect, got %v", err)
	}
	_ = resp.Body.Close()

	// Wrong pin: the TLS handshake is rejected.
	badPin := strings.Repeat("00", sha256.Size)
	badClient := deviceClient(5*time.Second, "", badPin)
	resp2, err := getWithContext(t, badClient, ts.URL)
	if err == nil {
		_ = resp2.Body.Close()
		t.Fatal("client with wrong pin must reject the device certificate")
	}
}
