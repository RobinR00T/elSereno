//go:build offensive

package main

import (
	"bytes"
	"strings"
	"testing"

	iaxwire "local/elsereno/internal/protocols/iax2/wire"
)

// ---- parseAllowEntry ------------------------------------------

func TestParseAllowEntry_Valid(t *testing.T) {
	cases := []struct {
		in         string
		wantMethod string
		wantPath   string
	}{
		{"POST:/admin/config.php", "POST", "/admin/config.php"},
		{"post:/admin/config.php", "POST", "/admin/config.php"}, // method upper-cased
		{"DELETE:/admin/user/42", "DELETE", "/admin/user/42"},
		{"PUT:/api/v1/extensions", "PUT", "/api/v1/extensions"},
		{"  PATCH  :  /conf  ", "PATCH", "/conf"}, // trimmed
	}
	for _, c := range cases {
		got, err := parseAllowEntry(c.in)
		if err != nil {
			t.Errorf("parseAllowEntry(%q) unexpected err: %v", c.in, err)
			continue
		}
		if got.Method != c.wantMethod {
			t.Errorf("parseAllowEntry(%q) method=%q, want %q", c.in, got.Method, c.wantMethod)
		}
		if got.Path != c.wantPath {
			t.Errorf("parseAllowEntry(%q) path=%q, want %q", c.in, got.Path, c.wantPath)
		}
	}
}

func TestParseAllowEntry_Invalid(t *testing.T) {
	invalid := []string{
		"",                  // empty
		"POST",              // no colon
		"POST/admin/config", // no colon (slash is not separator)
		":/path",            // empty method
		"POST:",             // empty path
		"POST:admin/config", // path doesn't start with /
		":",                 // both sides empty
	}
	for _, in := range invalid {
		if _, err := parseAllowEntry(in); err == nil {
			t.Errorf("parseAllowEntry(%q) expected error, got none", in)
		}
	}
}

// ---- iaxSubclassByName ----------------------------------------

func TestIAXSubclassByName_KnownValues(t *testing.T) {
	cases := []struct {
		name string
		want iaxwire.IAXSubclass
	}{
		{"NEW", iaxwire.IAXNew},
		{"new", iaxwire.IAXNew},   // case-insensitive
		{" NEW ", iaxwire.IAXNew}, // trimmed
		{"REGREQ", iaxwire.IAXRegreq},
		{"AUTHREP", iaxwire.IAXAuthRep},
		{"ACCEPT", iaxwire.IAXAccept},
	}
	for _, c := range cases {
		got, err := iaxSubclassByName(c.name)
		if err != nil {
			t.Errorf("iaxSubclassByName(%q): %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("iaxSubclassByName(%q) = 0x%02x, want 0x%02x", c.name, got, c.want)
		}
	}
}

func TestIAXSubclassByName_Unknown(t *testing.T) {
	for _, n := range []string{"", "HANGUP", "UNKNOWN", "ACK", "foo"} {
		if _, err := iaxSubclassByName(n); err == nil {
			t.Errorf("iaxSubclassByName(%q) expected error", n)
		}
	}
}

// ---- canonicalisation helpers ---------------------------------

func TestCanonMethods_SortsAndDedupes(t *testing.T) {
	in := []string{"invite", "INVITE", "REGISTER", "message"}
	got := canonMethods(in)
	// Expected: unique + sorted + upper — "INVITE, MESSAGE, REGISTER".
	if got != "INVITE, MESSAGE, REGISTER" {
		t.Errorf("canonMethods(%v) = %q, want INVITE, MESSAGE, REGISTER", in, got)
	}
}

func TestCanonMethods_Empty(t *testing.T) {
	got := canonMethods(nil)
	if !strings.Contains(got, "none") {
		t.Errorf("canonMethods(nil) = %q, want message containing 'none'", got)
	}
}

// ---- end-to-end: dry-run prints expected fields ---------------

func TestWriteSIPDryRun_OutputShape(t *testing.T) {
	cmd := newWriteSIPDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "pbx.example.com:5060", "--method", "INVITE"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Protocol:     sip",
		"Target:       pbx.example.com:5060",
		"Allowed:      INVITE",
		"Always-safe:  OPTIONS, ACK, BYE, CANCEL, PRACK",
		"PayloadHash:  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q; full output:\n%s", want, out)
		}
	}
}

func TestWriteIAX2DryRun_OutputShape(t *testing.T) {
	cmd := newWriteIAX2DryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "pbx.example.com:4569", "--subclass", "NEW", "--subclass", "REGREQ"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Protocol:     iax2", "Target:       pbx.example.com:4569", "Allowed:      NEW, REGREQ", "PayloadHash:  "} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, out)
		}
	}
}

func TestWritePBXHTTPDryRun_OutputShape(t *testing.T) {
	cmd := newWritePBXHTTPDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "pbx.example.com:443", "--allow", "POST:/admin/config.php"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Protocol:     pbxhttp", "Target:       pbx.example.com:443", "POST /admin/config.php", "PayloadHash:  "} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteSIPDryRun_RequiresTarget(t *testing.T) {
	cmd := newWriteSIPDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// Suppress cobra's auto-printing of usage on errors so tests
	// don't drown in noise.
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--method", "INVITE"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected --target-required error")
	}
}

// ---- OPC UA dry-run -------------------------------------------

func TestWriteOPCUADryRun_OutputShape(t *testing.T) {
	cmd := newWriteOPCUADryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc.example.com:4840",
		"--service", "673",
		"--service", "704",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Protocol:     opcua",
		"Target:       plc.example.com:4840",
		"Services:     673, 704",
		"NodeIDs:      (none",
		"PayloadHash:  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestWriteOPCUADryRun_WithNodeIDs(t *testing.T) {
	cmd := newWriteOPCUADryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc.example.com:4840",
		"--service", "673",
		"--node-id", "ns=2;i=42",
		"--node-id", "ns=3;i=100",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ns=2;i=42") || !strings.Contains(out, "ns=3;i=100") {
		t.Errorf("NodeIDs not rendered:\n%s", out)
	}
}

func TestWriteOPCUADryRun_ServiceOutOfRange(t *testing.T) {
	cmd := newWriteOPCUADryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "h:1", "--service", "70000"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected service-out-of-range error")
	}
}

// ---- BACnet dry-run -------------------------------------------

func TestWriteBACnetDryRun_OutputShape(t *testing.T) {
	cmd := newWriteBACnetDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "bms.example.com:47808",
		"--service-choice", "15",
		"--service-choice", "20",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Protocol:     bacnet",
		"Target:       bms.example.com:47808",
		"Services:     15, 20",
		"PayloadHash:  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestWriteBACnetDryRun_ServiceChoiceOutOfRange(t *testing.T) {
	cmd := newWriteBACnetDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "h:1", "--service-choice", "256"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected service-choice-out-of-range error")
	}
}

// ---- CWMP dry-run (v1.11+) -----------------------------------

func TestWriteCWMPDryRun_OutputShape(t *testing.T) {
	cmd := newWriteCWMPDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "acs.example.com:7547",
		"--rpc", "SetParameterValues",
		"--rpc", "Reboot",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Protocol:     cwmp",
		"Target:       acs.example.com:7547",
		"RPCs:         Reboot, SetParameterValues",
		"Always-safe:  GetParameter",
		"PayloadHash:  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestWriteCWMPDryRun_EmptyRPCsShowsHint(t *testing.T) {
	cmd := newWriteCWMPDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "acs.example.com:7547"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "(none — all write-capable RPCs refused; reads still pass)") {
		t.Errorf("empty-rpcs hint missing:\n%s", out)
	}
}

func TestWriteCWMPDryRun_RequiresTarget(t *testing.T) {
	cmd := newWriteCWMPDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--rpc", "Reboot"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --target-required error")
	}
}

func TestCanonCWMPRPCs(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, "(none — all write-capable RPCs refused; reads still pass)"},
		{[]string{"SetParameterValues", "Reboot"}, "Reboot, SetParameterValues"},
		{[]string{"cwmp:Reboot", " Reboot "}, "Reboot"}, // dedup + prefix strip
		{[]string{"Reboot", "SetParameterValues", "Download", "Reboot"}, "Download, Reboot, SetParameterValues"},
	}
	for _, c := range cases {
		got := canonCWMPRPCs(c.in)
		if got != c.want {
			t.Errorf("canonCWMPRPCs(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---- parseNodeIDFlag -----------------------------------------

func TestParseNodeIDFlag_Valid(t *testing.T) {
	cases := []struct {
		in     string
		wantNS uint16
		wantID uint32
	}{
		{"ns=2;i=42", 2, 42},
		{"ns=0;i=1", 0, 1},
		{" NS=5 ; I=999 ", 5, 999},
		{"ns=65535;i=4294967295", 65535, 4294967295},
	}
	for _, c := range cases {
		got, err := parseNodeIDFlag(c.in)
		if err != nil {
			t.Errorf("parseNodeIDFlag(%q): %v", c.in, err)
			continue
		}
		if got.Namespace != c.wantNS || got.Identifier != c.wantID {
			t.Errorf("parseNodeIDFlag(%q) = ns=%d;i=%d, want ns=%d;i=%d",
				c.in, got.Namespace, got.Identifier, c.wantNS, c.wantID)
		}
	}
}

func TestParseNodeIDFlag_Invalid(t *testing.T) {
	for _, in := range []string{
		"",               // empty
		"ns=2",           // missing i=
		"42;100",         // no key=
		"ns=abc;i=42",    // non-numeric ns
		"ns=65536;i=42",  // ns too big
		"ns=2;unknown=3", // unknown key
	} {
		if _, err := parseNodeIDFlag(in); err == nil {
			t.Errorf("parseNodeIDFlag(%q): expected error", in)
		}
	}
}
