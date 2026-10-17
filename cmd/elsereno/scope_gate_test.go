package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/scope"
)

// scopeTestEnv isolates HOME and writes a scope file.
func scopeTestEnv(t *testing.T, yaml string) (dir, scopePath string) {
	t.Helper()
	dir = t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("ELSERENO_CONFIG", "")
	scopePath = filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(scopePath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, scopePath
}

func runRoot(t *testing.T, args ...string) error {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return root.ExecuteContext(ctx)
}

func exitCode(err error) core.ExitCode {
	var ce cliError
	if errors.As(err, &ce) {
		return ce.code
	}
	if err == nil {
		return core.ExitOK
	}
	return core.ExitError
}

const outOfRangeScope = "version: 1\nranges:\n  - cidr: 192.0.2.0/24\n"

// TestScope_NetworkCommandsRefuseOutOfScope: every network command that
// takes --scope refuses a target outside its ranges with 77 and opens
// no connection. Until 2026-10-17 only scan, serve and dial took
// --scope (PITF-095).
func TestScope_NetworkCommandsRefuseOutOfScope(t *testing.T) {
	_, sp := scopeTestEnv(t, outOfRangeScope)
	addr, accepted, stop := countingListener(t)
	defer stop()
	cases := [][]string{
		{"fingerprint", "probe", "--plugin", "banner", "--target", addr},
		{"plaintext-check", "--target", addr},
		{"opcua", "probe-anon", "--target", addr},
		{"opcua", "probe-write", "--target", addr},
		{"s7", "probe", "--target", addr},
		{"s7", "probe-protection", "--target", addr},
		{"s7", "probe-identity", "--target", addr},
	}
	cases = append(cases, offensiveScopeCases(addr)...)
	for _, args := range cases {
		err := runRoot(t, append(args, "--scope", sp)...)
		if got := exitCode(err); got != core.ExitNoPerm {
			t.Errorf("%v: exit %d (%v), want 77", args, got, err)
		}
	}
	stop()
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the out-of-scope listener", n)
	}
}

// TestScope_InScopeTargetIsProbed: the gate lets an in-scope target
// through (positive control for the test above).
func TestScope_InScopeTargetIsProbed(t *testing.T) {
	_, sp := scopeTestEnv(t, "version: 1\nranges:\n  - cidr: 127.0.0.0/8\n")
	addr, accepted, stop := countingListener(t)
	defer stop()
	_ = runRoot(t, "fingerprint", "probe", "--plugin", "banner", "--target", addr, "--timeout", "2s", "--scope", sp)
	stop()
	if accepted.Load() == 0 {
		t.Fatal("an in-scope target got no connection")
	}
}

// TestScope_ProtocolsRefusePlugin: a plugin the protocols lists leave
// out is refused (77) before any connection, also in scan with
// --plugin.
func TestScope_ProtocolsRefusePlugin(t *testing.T) {
	dir, sp := scopeTestEnv(t, "version: 1\nranges:\n  - cidr: 127.0.0.0/8\nprotocols:\n  deny: [s7, banner]\n")
	addr, accepted, stop := countingListener(t)
	defer stop()
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte(addr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"fingerprint", "probe", "--plugin", "banner", "--target", addr},
		{"s7", "probe", "--target", addr},
		{"scan", "--input", "list:" + list, "--plugin", "banner", "--no-progress", "--output", filepath.Join(dir, "out.ndjson")},
	}
	for _, args := range cases {
		if got := exitCode(runRoot(t, append(args, "--scope", sp)...)); got != core.ExitNoPerm {
			t.Errorf("%v: exit %d, want 77", args, got)
		}
	}
	stop()
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections despite the protocols deny", n)
	}
}

// TestScope_BadFileIsConfigError: a scope file that does not parse
// stops the command with 78 rather than running it unscoped.
func TestScope_BadFileIsConfigError(t *testing.T) {
	_, sp := scopeTestEnv(t, "version: 1\nrangez: []\n")
	addr, accepted, stop := countingListener(t)
	defer stop()
	if got := exitCode(runRoot(t, "plaintext-check", "--target", addr, "--scope", sp)); got != core.ExitConfig {
		t.Errorf("exit %d, want 78", got)
	}
	stop()
	if accepted.Load() != 0 {
		t.Fatal("a bad scope file let the command connect")
	}
}

// TestScope_DiscoverAndTUIInput: discover and tui --input drop hosts
// outside the ranges and stop with 66 when none is left.
func TestScope_DiscoverAndTUIInput(t *testing.T) {
	dir, sp := scopeTestEnv(t, outOfRangeScope)
	hosts := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(hosts, []byte("127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := exitCode(runRoot(t, "discover", "--hosts", hosts, "--scope", sp)); got != core.ExitNoInput {
		t.Errorf("discover: exit %d, want 66", got)
	}
	list := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(list, []byte("127.0.0.1:502\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := exitCode(tuiInputFeedErr(t, "list:"+list, sp)); got != core.ExitNoInput && !tuiAbsent() {
		t.Errorf("tui --input: exit %d, want 66", got)
	}
}

// TestScopeGate_HostPortAndURL: the gate returns the checked IP to
// connect to, refuses a name for write-class verbs, and derives the
// port of a URL from its scheme.
func TestScopeGate_HostPortAndURL(t *testing.T) {
	ctx := context.Background()
	open := scopeGate{}
	if got, err := open.hostPort(ctx, "plc.invalid:502", "modbus"); err != nil || got != "plc.invalid:502" {
		t.Fatalf("no scope: %q %v, want the input untouched and no lookup", got, err)
	}
	g := scopeGate{sc: &scope.Scope{Ranges: []scope.RangeDecl{{CIDR: "127.0.0.0/8"}, {CIDR: "::1/128"}}}}
	got, err := g.hostPort(ctx, "localhost:502", "modbus")
	if err != nil {
		t.Fatal(err)
	}
	if ap, perr := netip.ParseAddrPort(got); perr != nil || !ap.Addr().IsLoopback() || ap.Port() != 502 {
		t.Fatalf("hostPort(localhost:502) = %q, want a loopback IP:502", got)
	}
	if exitCode(g.literalTarget("localhost:502", "modbus")) != core.ExitUsage {
		t.Error("literalTarget accepted a name with a scope")
	}
	if exitCode(g.literalTarget("192.0.2.1:502", "modbus")) != core.ExitNoPerm {
		t.Error("literalTarget accepted an out-of-range IP")
	}
	if err := (scopeGate{}).literalTarget("localhost:502", "modbus"); err != nil {
		t.Errorf("literalTarget without a scope: %v", err)
	}
	for in, want := range map[string]string{
		"http://127.0.0.1/":       "127.0.0.1:80",
		"https://127.0.0.1/login": "127.0.0.1:443",
		"http://127.0.0.1:8080/":  "127.0.0.1:8080",
	} {
		if got, err := g.urlDialAddr(ctx, in, "http-basic"); err != nil || got != want {
			t.Errorf("urlDialAddr(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	if exitCode(func() error { _, err := g.urlDialAddr(ctx, "ftp://127.0.0.1/", ""); return err }()) != core.ExitUsage {
		t.Error("urlDialAddr accepted a scheme with no default port")
	}
}

// TestScopePlugins: named plugins the scope refuses stop the scan;
// without names the refused ones are left out and reported.
func TestScopePlugins(t *testing.T) {
	sc := &scope.Scope{Protocols: scope.ProtoDecl{Deny: []string{"s7"}}}
	plugins := []core.Plugin{
		{PluginMetadata: core.PluginMetadata{Name: "modbus"}},
		{PluginMetadata: core.PluginMetadata{Name: "s7"}},
		{PluginMetadata: core.PluginMetadata{Name: "s7-exposure"}},
	}
	if _, _, err := scopePlugins(sc, true, plugins); exitCode(err) != core.ExitNoPerm {
		t.Fatalf("named: %v, want 77", err)
	}
	kept, refused, err := scopePlugins(sc, false, plugins)
	if err != nil || len(kept) != 1 || kept[0].Name != "modbus" || len(refused) != 2 {
		t.Fatalf("unnamed: kept %v refused %v err %v", kept, refused, err)
	}
	if kept, _, _ := scopePlugins(nil, true, plugins); len(kept) != 3 {
		t.Fatal("nil scope dropped plugins")
	}
}

// TestScanRunner_ProtocolsApply: dashboard scans apply the protocols
// lists as scan does: a named plugin the scope refuses fails the job
// (77), an unnamed one is left out, and neither connects.
func TestScanRunner_ProtocolsApply(t *testing.T) {
	addr, accepted, stop := countingListener(t)
	defer stop()
	list := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(list, []byte(addr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &defaultScanRunner{scope: &scope.Scope{Protocols: scope.ProtoDecl{Deny: []string{"banner"}}}}
	ctx := context.Background()
	if _, _, err := r.Run(ctx, scanorch.Job{ID: "named", Input: "list:" + list, Plugins: []string{"banner"}}, nil); exitCode(err) != core.ExitNoPerm {
		t.Errorf("named refused plugin: %v, want exit 77", err)
	}
	// Unnamed: banner is the only plugin for a random port, so nothing
	// is left to run.
	if _, _, err := r.Run(ctx, scanorch.Job{ID: "all", Input: "list:" + list}, nil); !errors.Is(err, ErrRunnerNoMatchingPlugins) {
		t.Errorf("unnamed: %v, want ErrRunnerNoMatchingPlugins", err)
	}
	stop()
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections despite protocols deny: [banner]", n)
	}
}
