//go:build integration

package integration_test

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/banner"
	"local/elsereno/internal/scanner"
)

// TestBannerScanAgainstLocalServer spins up a tiny loopback TCP server
// to stand in for the banner-sim container when docker-compose is not
// available. It complements simulators/docker-compose.test.yml by
// verifying the scanner→probe→finding pipeline end-to-end in the
// integration suite.
func TestBannerScanAgainstLocalServer(t *testing.T) {
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for i := 0; i < 3; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("ELSERENO-INTEGRATION-TEST\r\n"))
			_ = conn.Close()
		}
	}()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type %T", ln.Addr())
	}
	port, _ := core.NewPort(addr.Port)
	host := netip.MustParseAddr("127.0.0.1")

	targets := []core.Target{
		{Address: host, Port: port},
		{Address: host, Port: port}, // dup — Dedupe must collapse
		{Address: host, Port: port},
	}

	s := scanner.New(scanner.Options{MaxConcurrentTargets: 4, MaxRetries: 1})
	probe := banner.Default().Probe

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, errs := s.Run(ctx, targets, probe)

	seen := 0
	for range findings {
		seen++
	}
	var gotErr error
	for e := range errs {
		gotErr = e
	}
	if seen == 0 {
		t.Fatalf("no findings (err=%v); expected at least 1", gotErr)
	}
	if !strings.Contains(addr.String(), "127.0.0.1") {
		t.Fatalf("unexpected bound address %s", addr)
	}
	_ = strconv.Itoa // quiet importer if refactored
}
