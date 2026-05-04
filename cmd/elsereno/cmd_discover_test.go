package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExpandCIDR_IPv4Slash30 — /30 prefix should yield 4
// consecutive addresses (the network + 2 hosts + broadcast)
// when maxHosts is unlimited.
func TestExpandCIDR_IPv4Slash30(t *testing.T) {
	addrs, err := expandCIDR("192.168.1.0/30", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 4 {
		t.Fatalf("got %d addrs, want 4", len(addrs))
	}
	wantFirst, wantLast := "192.168.1.0", "192.168.1.3"
	if addrs[0].String() != wantFirst {
		t.Errorf("addrs[0] = %s, want %s", addrs[0], wantFirst)
	}
	if addrs[3].String() != wantLast {
		t.Errorf("addrs[3] = %s, want %s", addrs[3], wantLast)
	}
}

// TestExpandCIDR_MaxHostsCap — maxHosts caps the output even
// for a large prefix. /16 = 65k addrs but maxHosts=10 limits.
func TestExpandCIDR_MaxHostsCap(t *testing.T) {
	addrs, err := expandCIDR("10.0.0.0/16", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 10 {
		t.Errorf("got %d addrs, want 10 (maxHosts cap)", len(addrs))
	}
}

// TestExpandCIDR_IPv6Slash126 — IPv6 /126 yields 4 addrs.
// Validates the v6 path through expandCIDR (chunk 4 of v1.14
// pinned the contract upstream).
func TestExpandCIDR_IPv6Slash126(t *testing.T) {
	addrs, err := expandCIDR("2001:db8::/126", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 4 {
		t.Fatalf("got %d addrs, want 4 for /126", len(addrs))
	}
	if addrs[0].String() != "2001:db8::" {
		t.Errorf("addrs[0] = %s, want 2001:db8::", addrs[0])
	}
}

// TestExpandCIDR_BadInput — malformed CIDRs return errors with
// the original input echoed back so operators see what they
// typed.
func TestExpandCIDR_BadInput(t *testing.T) {
	_, err := expandCIDR("not-a-cidr", 0)
	if err == nil {
		t.Fatal("expected error for malformed CIDR")
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Errorf("error should echo input: %v", err)
	}
}

// TestPluginsForPort_SharedPortListsAll — the shared-port
// case (e.g. svc 102 used by both s7 and IEC 61850 MMS in
// future). Verifies pluginsForPort returns every claimant.
func TestPluginsForPort_SharedPortListsAll(t *testing.T) {
	ports := []pluginPort{
		{Port: 102, PluginID: "s7"},
		{Port: 102, PluginID: "iec61850-mms"}, // hypothetical
		{Port: 502, PluginID: "modbus"},
	}
	got := pluginsForPort(ports, 102)
	if len(got) != 2 {
		t.Errorf("expected 2 plugins for port 102, got %v", got)
	}
}

// TestPluginsForPort_NoMatch — port not in the list returns
// nil (callers handle that as "unknown port responded — log
// without protocol hint").
func TestPluginsForPort_NoMatch(t *testing.T) {
	ports := []pluginPort{{Port: 502, PluginID: "modbus"}}
	got := pluginsForPort(ports, 9999)
	if len(got) != 0 {
		t.Errorf("expected nil, got %v", got)
	}
}

// TestSweep_RespondingPortDetected — boot a tiny TCP listener,
// have the sweep target it, verify we see the hit.
func TestSweep_RespondingPortDetected(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	addrPort, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	hosts := []netip.Addr{addrPort.Addr()}
	ports := []pluginPort{{Port: int(addrPort.Port()), PluginID: "test-plugin"}}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hits := sweep(ctx, hosts, ports, 4, 500*time.Millisecond)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1: %+v", len(hits), hits)
	}
	if hits[0].Port != int(addrPort.Port()) {
		t.Errorf("hits[0].Port = %d", hits[0].Port)
	}
	if len(hits[0].ProtocolHints) != 1 || hits[0].ProtocolHints[0] != "test-plugin" {
		t.Errorf("hits[0].ProtocolHints = %v", hits[0].ProtocolHints)
	}
}

// TestSweep_DeadPortIgnored — a closed port produces no hit.
// Use a port we're sure isn't listening (random in the
// ephemeral range without a listener).
func TestSweep_DeadPortIgnored(t *testing.T) {
	hosts := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	// Port 1 is reserved + almost certainly not listening on
	// loopback. The connect should fail fast.
	ports := []pluginPort{{Port: 1, PluginID: "test-plugin"}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hits := sweep(ctx, hosts, ports, 4, 200*time.Millisecond)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits, got %d: %+v", len(hits), hits)
	}
}

// TestEmitDiscoverResults_NDJSON — output format ndjson
// produces one JSON object per line.
func TestEmitDiscoverResults_NDJSON(t *testing.T) {
	hits := []discoverHit{
		{Address: "192.168.1.5", Port: 502, ProtocolHints: []string{"modbus"}, LatencyMS: 12},
		{Address: "192.168.1.5", Port: 47808, ProtocolHints: []string{"bacnet"}, LatencyMS: 18},
	}
	var stdout, stderr bytes.Buffer
	if err := emitDiscoverResults(&stdout, &stderr, hits, "ndjson"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 ndjson lines, got %d:\n%s", len(lines), stdout.String())
	}
	if !strings.Contains(stderr.String(), "2 responsive") {
		t.Errorf("stderr should report count: %q", stderr.String())
	}
}

// TestEmitDiscoverResults_List — list format emits host:port
// pairs (pipe-friendly with `scan --input list:-`).
func TestEmitDiscoverResults_List(t *testing.T) {
	hits := []discoverHit{
		{Address: "192.168.1.5", Port: 502},
		{Address: "2001:db8::1", Port: 47808},
	}
	var stdout, stderr bytes.Buffer
	if err := emitDiscoverResults(&stdout, &stderr, hits, "list"); err != nil {
		t.Fatal(err)
	}
	got := stdout.String()
	if !strings.Contains(got, "192.168.1.5:502") {
		t.Errorf("missing v4: %q", got)
	}
	if !strings.Contains(got, "[2001:db8::1]:47808") {
		t.Errorf("missing v6 with brackets: %q", got)
	}
}

// TestEmitDiscoverResults_BadFormat — unknown format errors.
func TestEmitDiscoverResults_BadFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := emitDiscoverResults(&stdout, &stderr, nil, "yaml")
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

// TestLoadDiscoverHostsFile_HappyPath — minimal file with
// IP per line + comments + blank lines parses cleanly.
func TestLoadDiscoverHostsFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	body := `# comments allowed
127.0.0.1
10.0.0.1

192.0.2.5  # inline comment after IP
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	hosts, err := loadDiscoverHostsFile(path, 0)
	if err != nil {
		t.Fatalf("loadDiscoverHostsFile: %v", err)
	}
	if got := len(hosts); got != 3 {
		t.Errorf("hosts = %d, want 3", got)
	}
	wantStrs := []string{"127.0.0.1", "10.0.0.1", "192.0.2.5"}
	for i, w := range wantStrs {
		if hosts[i].String() != w {
			t.Errorf("hosts[%d] = %q, want %q", i, hosts[i].String(), w)
		}
	}
}

// TestLoadDiscoverHostsFile_HostPortStrip — operator pasting
// `host:port` lines works (we strip the port half).
func TestLoadDiscoverHostsFile_HostPortStrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	body := "10.0.0.1:502\n10.0.0.2:443\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	hosts, err := loadDiscoverHostsFile(path, 0)
	if err != nil {
		t.Fatalf("loadDiscoverHostsFile: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts = %d, want 2", len(hosts))
	}
	if hosts[0].String() != "10.0.0.1" {
		t.Errorf("hosts[0] = %q, want 10.0.0.1", hosts[0].String())
	}
}

// TestLoadDiscoverHostsFile_IPv6Preserved — ipv6 with double-
// colon retains its full form (port-strip skips IPv6).
func TestLoadDiscoverHostsFile_IPv6Preserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	body := "2001:db8::1\nfe80::1\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	hosts, err := loadDiscoverHostsFile(path, 0)
	if err != nil {
		t.Fatalf("loadDiscoverHostsFile: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts = %d, want 2", len(hosts))
	}
	if hosts[0].String() != "2001:db8::1" {
		t.Errorf("hosts[0] = %q, want 2001:db8::1", hosts[0].String())
	}
}

// TestLoadDiscoverHostsFile_MaxHostsCap — bounded walk.
func TestLoadDiscoverHostsFile_MaxHostsCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	body := "10.0.0.1\n10.0.0.2\n10.0.0.3\n10.0.0.4\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	hosts, err := loadDiscoverHostsFile(path, 2)
	if err != nil {
		t.Fatalf("loadDiscoverHostsFile: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("hosts = %d, want 2 (max-hosts cap)", len(hosts))
	}
}

// TestLoadDiscoverHostsFile_EmptyFile — file with no IPs at
// all → typed error.
func TestLoadDiscoverHostsFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(path, []byte("# only comments\n\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadDiscoverHostsFile(path, 0)
	if err == nil || !strings.Contains(err.Error(), "no hosts parsed") {
		t.Errorf("err = %v, want 'no hosts parsed'", err)
	}
}

// TestLoadDiscoverHostsFile_BadIP — line that doesn't parse
// as a netip.Addr surfaces with file + line context.
func TestLoadDiscoverHostsFile_BadIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	body := "10.0.0.1\nNOT-AN-IP\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadDiscoverHostsFile(path, 0)
	if err == nil {
		t.Fatal("expected error on bad IP")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("err = %v, want 'line 2' context", err)
	}
}

// TestLoadDiscoverHostsFile_MissingFile — wrapped open error.
func TestLoadDiscoverHostsFile_MissingFile(t *testing.T) {
	_, err := loadDiscoverHostsFile(filepath.Join(t.TempDir(), "no-such.txt"), 0)
	if err == nil {
		t.Fatal("expected open error")
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("err = %v, want 'no such file'", err)
	}
}
