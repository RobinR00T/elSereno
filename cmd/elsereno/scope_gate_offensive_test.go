//go:build offensive

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

// offensiveScopeCases are the offensive verbs that connect to a
// target. Each is refused before the vault, the sandbox or the
// confirm token are read.
func offensiveScopeCases(addr string) [][]string {
	return [][]string{
		{"write", "modbus", "send", "--target", addr, "--accept-writes",
			"--confirm-target", addr, "--confirm-token", "x", "--op", "write-single-register", "--address", "1", "--value", "1"},
		{"exploit", "run", "--cve", "CVE-2019-10953", "--target", addr, "--accept-writes",
			"--confirm-target", addr, "--confirm-token", "x"},
		{"harvest", "telnet", "--target", addr},
		{"creds-check", "http", "--target", "http://" + addr + "/", "--confirm-authorized"},
		{"proxy", "listen", "--plugin", "modbus", "--target", addr, "--listen", "127.0.0.1:0",
			"--function", "6", "--accept-writes", "--confirm-target", addr, "--confirm-token", "x",
			"--vault-passphrase-file", "unused.pp"},
	}
}

// TestScope_WriteVerbsNeedIPLiteral: with --scope, a write-class verb
// refuses a name (64): its confirm token covers the target as typed,
// so the gate cannot swap in the resolved address.
func TestScope_WriteVerbsNeedIPLiteral(t *testing.T) {
	_, sp := scopeTestEnv(t, "version: 1\nranges:\n  - cidr: 127.0.0.0/8\n")
	err := runRoot(t, "write", "modbus", "send", "--target", "localhost:502", "--accept-writes",
		"--confirm-target", "localhost:502", "--confirm-token", "x",
		"--op", "write-single-register", "--address", "1", "--value", "1", "--scope", sp)
	if got := exitCode(err); got != core.ExitUsage {
		t.Fatalf("exit %d (%v), want 64", got, err)
	}
}

// TestCredsCheck_PinsDialToCheckedAddress: with --scope the requests go
// to the address the gate checked, whatever the URL's host resolves to
// afterwards: here the URL names a closed port and only the pinned
// address answers.
func TestCredsCheck_PinsDialToCheckedAddress(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	closed, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + closed.Addr().String() + "/"
	_ = closed.Close()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(io.Discard)
	if err := runCredsCheckHTTP(cmd, url, strings.TrimPrefix(srv.URL, "http://"), 5*time.Second, false); err != nil {
		t.Fatalf("runCredsCheckHTTP: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("pinned address got %d requests, want 1", hits.Load())
	}
}

// TestCredsCheck_CommandPinsResolvedAddress: through the command, with
// --scope, a URL host that resolves to two loopback addresses is
// checked and connected to as its first one only. The server listens
// on the other one and must get nothing; without the pin, the dialer
// would fall back to it.
func TestCredsCheck_CommandPinsResolvedAddress(t *testing.T) {
	addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", "localhost")
	if err != nil || len(addrs) < 2 {
		t.Skipf("localhost resolves to %v (%v); need both loopback families", addrs, err)
	}
	first := addrs[0].Unmap()
	var other netip.Addr
	for _, a := range addrs[1:] {
		if a.Unmap().Is4() != first.Is4() {
			other = a.Unmap()
			break
		}
	}
	if !other.IsValid() {
		t.Skip("localhost has no second address family")
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", netip.AddrPortFrom(other, 0).String())
	if err != nil {
		t.Skipf("listen on %s: %v", other, err)
	}
	var hits atomic.Int32
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T", ln.Addr())
	}
	port := tcp.Port
	_, sp := scopeTestEnv(t, "version: 1\nranges:\n  - cidr: "+netip.PrefixFrom(first, first.BitLen()).String()+"\n")
	_ = runRoot(t, "creds-check", "http", "--target", "http://localhost:"+strconv.Itoa(port)+"/",
		"--confirm-authorized", "--timeout", "3s", "--scope", sp)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the unchecked address %s got %d requests", other, n)
	}
}
