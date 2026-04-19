package atmodem_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/atmodem"
)

// atSim is a tiny TCP server that emulates a small AT modem. The
// `script` map returns a fixed response per exact command line; any
// unknown line falls back to ERROR.
func atSim(t *testing.T, script map[string]string) *net.TCPAddr {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, script)
		}
	}()
	return addr
}

func serve(conn net.Conn, script map[string]string) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	rd := bufio.NewReader(conn)
	for {
		line, err := rd.ReadString('\r')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(strings.TrimRight(line, "\r"))
		resp, ok := script[cmd]
		if !ok {
			resp = "ERROR"
		}
		_, _ = conn.Write([]byte(resp + "\r\n"))
	}
}

func TestProbeOKAndFingerprint(t *testing.T) {
	t.Parallel()
	addr := atSim(t, map[string]string{
		"AT":      "OK",
		"ATI":     "Siemens TC35i\r\nREVISION 04.04\r\nOK",
		"AT+CGMI": "Siemens\r\nOK",
	})
	p := atmodem.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 1 * time.Second
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}

	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Protocol != atmodem.Name {
		t.Fatalf("Protocol=%q", f.Protocol)
	}
	if f.Score < 0 || f.Score > 100 {
		t.Fatalf("Score out of range: %d", f.Score)
	}
}

func TestProbeATFailsEmitsInfo(t *testing.T) {
	t.Parallel()
	addr := atSim(t, map[string]string{
		"AT": "NO CARRIER",
	})
	p := atmodem.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 500 * time.Millisecond
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Severity != core.SeverityInfo && f.Severity != core.SeverityLow {
		t.Fatalf("Severity=%s", f.Severity)
	}
}

func TestIsForbiddenCommand(t *testing.T) {
	t.Parallel()
	blocked := []string{
		"ATD112",
		"ATD+34112345",
		"atd00",
		"  ATA",
		"AT+CMGS=\"+34...\"",
		"AT+CMGW",
		"AT+CFUN=0",
		"AT+CPWROFF",
		"+++",
	}
	for _, line := range blocked {
		if !atmodem.IsForbiddenCommand(line) {
			t.Fatalf("expected blocked: %q", line)
		}
	}
	allowed := []string{
		"AT",
		"ATI",
		"AT+CGMI",
		"AT+CPIN?",
		"",
	}
	for _, line := range allowed {
		if atmodem.IsForbiddenCommand(line) {
			t.Fatalf("unexpectedly blocked: %q", line)
		}
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	md := atmodem.Default().Metadata()
	if md.Name != atmodem.Name {
		t.Fatalf("Name=%q", md.Name)
	}
	if md.Build != "default" {
		t.Fatalf("Build=%q", md.Build)
	}
}
