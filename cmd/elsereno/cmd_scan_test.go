package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
)

func target(t *testing.T, s string) core.Target {
	t.Helper()
	ap := netip.MustParseAddrPort(s)
	return core.Target{Address: ap.Addr(), Port: core.Port(ap.Port())}
}

// TestPlanScan_DispatchesProtocolPluginsByPort: with no --plugin the CLI
// runs every non-opt-in plugin on the targets of its default port, and
// banner on all of them. Until 2026-10-07 `scan` ran banner alone, so no
// protocol plugin ever ran from the CLI.
func TestPlanScan_DispatchesProtocolPluginsByPort(t *testing.T) {
	plugins, err := resolvePlugins(nil)
	if err != nil {
		t.Fatal(err)
	}
	targets := []core.Target{
		target(t, "127.0.0.1:20000"),
		target(t, "127.0.0.1:502"),
		target(t, "127.0.0.1:9"),
	}
	runs, total := planScan(plugins, targets)
	got := map[string]int{}
	for _, r := range runs {
		got[r.plugin.Name] = len(r.targets)
	}
	for name, want := range map[string]int{"banner": 3, "dnp3": 1, "modbus": 1} {
		if got[name] != want {
			t.Errorf("%s probes %d targets, want %d (runs: %v)", name, got[name], want, got)
		}
	}
	for _, optIn := range []string{"s7-exposure", "opcua-exposure", "codesys-active"} {
		if _, ok := got[optIn]; ok {
			t.Errorf("opt-in plugin %s ran without being named", optIn)
		}
	}
	if total != 5 {
		t.Errorf("total probes %d, want 5 (banner 3 + dnp3 1 + modbus 1)", total)
	}
}

// TestPlanScan_NamedPluginStillMatchesByPort: a named plugin only probes
// the targets on its default port (fingerprint probe covers other ports).
func TestPlanScan_NamedPluginStillMatchesByPort(t *testing.T) {
	plugins, err := resolvePlugins([]string{"dnp3"})
	if err != nil {
		t.Fatal(err)
	}
	if runs, _ := planScan(plugins, []core.Target{target(t, "127.0.0.1:20001")}); len(runs) != 0 {
		t.Fatalf("dnp3 on port 20001: %d runs, want 0", len(runs))
	}
	if runs, _ := planScan(plugins, []core.Target{target(t, "127.0.0.1:20000")}); len(runs) != 1 {
		t.Fatalf("dnp3 on port 20000: %d runs, want 1", len(runs))
	}
}

// TestExecScan_FindingsCarryTargetAddressAndPort runs the real scan path
// (banner) against a local listener and checks the NDJSON record names
// the target. Until 2026-10-07 every record had "address":"" and "port":0.
func TestExecScan_FindingsCarryTargetAddressAndPort(t *testing.T) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = c.Close()
		}
	}()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %T", ln.Addr())
	}
	tg := target(t, addr.AddrPort().String())

	var out bytes.Buffer
	opts := scanOpts{outputFormat: "ndjson", noProgress: true, retries: 0, plugins: []string{"banner"}}
	cfg := config.Config{}
	cfg.Scanner.MaxConcurrentTargets = 4
	cfg.Scanner.MaxConcurrentPerHost = 4
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := execScan(ctx, cfg, opts, []core.Target{tg}, &out); err != nil {
		t.Fatalf("execScan: %v", err)
	}
	line := strings.TrimSpace(out.String())
	var rec struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	if rec.Address != "127.0.0.1" || rec.Port != int(tg.Port) || rec.Protocol != "banner" {
		t.Fatalf("record = %+v, want address 127.0.0.1 port %d protocol banner", rec, tg.Port)
	}
}

// TestParseInput_ListDashReadsStdin: `list:-` is the documented way to
// pipe `discover --format list` into scan; it used to fail with
// "open -: no such file or directory".
func TestParseInput_ListDashReadsStdin(t *testing.T) {
	got, err := parseInput(context.Background(), inputParseOpts{
		InputKind: "list:-",
		Stdin:     strings.NewReader("127.0.0.1:20000\n127.0.0.1:502\n"),
	})
	if err != nil {
		t.Fatalf("parseInput(list:-): %v", err)
	}
	if len(got) != 2 || got[0].Port != 20000 || got[1].Port != 502 {
		t.Fatalf("targets = %+v", got)
	}
}

// TestExecScan_EachFindingKeepsItsOwnTarget: eight listeners that all
// send the same banner give eight banner findings with the same ID
// (banner's ID hashed only the banner bytes). Every record must still
// carry its own port. The first version of the scan fix looked the
// target up by finding ID after the fact, so records swapped targets
// (review, 2026-10-07).
func TestExecScan_EachFindingKeepsItsOwnTarget(t *testing.T) {
	const n = 8
	var targets []core.Target
	want := map[int]bool{}
	for i := 0; i < n; i++ {
		lc := net.ListenConfig{}
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("same banner everywhere\r\n"))
				_ = c.Close()
			}
		}()
		addr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			t.Fatalf("listener address %T", ln.Addr())
		}
		targets = append(targets, target(t, addr.AddrPort().String()))
		want[addr.Port] = true
	}
	var out bytes.Buffer
	opts := scanOpts{outputFormat: "ndjson", noProgress: true, plugins: []string{"banner"}}
	cfg := config.Config{}
	cfg.Scanner.MaxConcurrentTargets = n
	cfg.Scanner.MaxConcurrentPerHost = n
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := execScan(ctx, cfg, opts, targets, &out); err != nil {
		t.Fatalf("execScan: %v", err)
	}
	got := map[int]int{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var rec struct {
			Port int `json:"port"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		got[rec.Port]++
	}
	for p := range want {
		if got[p] != 1 {
			t.Errorf("port %d appears %d times in the output, want once (got %v)", p, got[p], got)
		}
	}
}

// TestWarnOptInAnyPort: a named opt-in plugin without a default port is
// announced, since it probes every listed target whatever the port.
func TestWarnOptInAnyPort(t *testing.T) {
	plugins, err := resolvePlugins([]string{"s7-exposure", "dnp3"})
	if err != nil {
		t.Fatal(err)
	}
	runs, _ := planScan(plugins, []core.Target{target(t, "127.0.0.1:502"), target(t, "127.0.0.1:20000")})
	var buf bytes.Buffer
	warnOptInAnyPort(&buf, runs)
	if !strings.Contains(buf.String(), "s7-exposure") || strings.Contains(buf.String(), "dnp3") {
		t.Fatalf("warning = %q, want one for s7-exposure only", buf.String())
	}
}
