//go:build offensive

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// helperCmd returns a throwaway cobra.Command that captures
// output into buf. Used because emitAllowFile writes through
// cmd.Printf which routes via cmd.Out().
func helperCmd(buf *bytes.Buffer) *cobra.Command {
	c := &cobra.Command{}
	c.SetOut(buf)
	c.SetErr(buf)
	return c
}

// ---- emitAllowFile round-trip --------------------------------

func TestEmitAllowFile_SIPStdout(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileSIP("pbx.example.com:5060", []string{"invite", "REGISTER", "invite"})
	if err := emitAllowFile(cmd, "-", af); err != nil {
		t.Fatalf("emitAllowFile: %v", err)
	}
	out := buf.String()
	// Canonicalised + deduped.
	if !strings.Contains(out, "plugin: sip") {
		t.Errorf("missing plugin field:\n%s", out)
	}
	if !strings.Contains(out, "target: pbx.example.com:5060") {
		t.Errorf("missing target:\n%s", out)
	}
	if !strings.Contains(out, "- INVITE") || !strings.Contains(out, "- REGISTER") {
		t.Errorf("methods not canonicalised/included:\n%s", out)
	}
	// Should NOT include any of the other plugin fields
	// (omitempty guarantees this).
	for _, stray := range []string{"subclasses:", "allow:", "functions:", "services:", "service_choices:"} {
		if strings.Contains(out, stray) {
			t.Errorf("unexpected field %q in sip output:\n%s", stray, out)
		}
	}
}

func TestEmitAllowFile_IAX2Stdout(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileIAX2("pbx:4569", []string{"new", "REGREQ"})
	if err := emitAllowFile(cmd, "-", af); err != nil {
		t.Fatalf("emitAllowFile: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "plugin: iax2") {
		t.Errorf("missing plugin: %s", out)
	}
	if !strings.Contains(out, "- NEW") || !strings.Contains(out, "- REGREQ") {
		t.Errorf("subclasses not canonicalised:\n%s", out)
	}
}

func TestEmitAllowFile_PBXHTTPStdout(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFilePBXHTTP("pbx:443", []string{"POST:/admin/config.php", "DELETE:/admin/user/42"})
	if err := emitAllowFile(cmd, "-", af); err != nil {
		t.Fatalf("emitAllowFile: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "plugin: pbxhttp") {
		t.Errorf("missing plugin: %s", out)
	}
	for _, want := range []string{"POST:/admin/config.php", "DELETE:/admin/user/42"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing allow entry %q:\n%s", want, out)
		}
	}
}

func TestEmitAllowFile_WritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileSIP("pbx:5060", []string{"INVITE"})
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emitAllowFile: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304 — `path` is a freshly-constructed test tempdir path, not untrusted input
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(data), "plugin: sip") {
		t.Errorf("file missing plugin: %s", string(data))
	}
	// 0600 permissions.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("perms %o: want no group/world access", fi.Mode().Perm())
	}
}

// ---- Round-trip: emit → load ---------------------------------

func TestEmitAllowFile_RoundTripSIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	if err := emitAllowFile(cmd, path, buildAllowFileSIP("pbx:5060", []string{"INVITE", "REGISTER"})); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if opts.plugin != "sip" {
		t.Errorf("plugin=%q, want sip", opts.plugin)
	}
	if len(opts.methods) != 2 {
		t.Errorf("methods=%v, want 2 entries", opts.methods)
	}
}

func TestEmitAllowFile_RoundTripPBXHTTP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	entries := []string{"POST:/admin/config.php", "DELETE:/admin/user/42"}
	if err := emitAllowFile(cmd, path, buildAllowFilePBXHTTP("pbx:443", entries)); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if opts.plugin != "pbxhttp" {
		t.Errorf("plugin=%q", opts.plugin)
	}
	if len(opts.allowEntries) != 2 {
		t.Errorf("allow entries=%v", opts.allowEntries)
	}
}

// TestEmitAllowFile_RoundTripOPCUAWithNodeIDs — closes the v1.6
// → v1.9 gap: the emitted YAML contains `node_ids:` entries and
// loadAllowFile materialises them back onto
// proxyListenOpts.nodeIDs in CLI-friendly `ns=N;i=M` form.
func TestEmitAllowFile_RoundTripOPCUAWithNodeIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)

	services := []uint{673, 704}
	nodeIDs := []string{"ns=3;i=100", "ns=2;i=42"} // unordered on purpose
	af := buildAllowFileOPCUA("plc.example.com:4840", services, nodeIDs)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}

	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if opts.plugin != "opcua" {
		t.Errorf("plugin=%q, want opcua", opts.plugin)
	}
	if len(opts.services) != 2 {
		t.Errorf("services=%v", opts.services)
	}
	// NodeIDs are stored sorted numerically by (ns, id) in the
	// emitter, so after round-trip they should come back sorted.
	if len(opts.nodeIDs) != 2 {
		t.Fatalf("nodeIDs=%v, want 2 entries", opts.nodeIDs)
	}
	if opts.nodeIDs[0] != "ns=2;i=42" {
		t.Errorf("nodeIDs[0] = %q, want ns=2;i=42 (sorted)", opts.nodeIDs[0])
	}
	if opts.nodeIDs[1] != "ns=3;i=100" {
		t.Errorf("nodeIDs[1] = %q, want ns=3;i=100 (sorted)", opts.nodeIDs[1])
	}
}

func TestEmitAllowFile_OPCUAOmitsNodeIDsWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileOPCUA("plc:4840", []uint{673}, nil)
	if err := emitAllowFile(cmd, "-", af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "node_ids") {
		t.Errorf("node_ids should be omitted when list empty:\n%s", out)
	}
}

// ---- ensureAllowFilePath -------------------------------------

func TestEnsureAllowFilePath_Empty(t *testing.T) {
	_, err := ensureAllowFilePath("")
	if !errors.Is(err, errEmitAllowFileNotSet) {
		t.Fatalf("expected errEmitAllowFileNotSet, got %v", err)
	}
}

func TestEnsureAllowFilePath_TrimsSpace(t *testing.T) {
	p, err := ensureAllowFilePath("  /tmp/allow.yaml  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != "/tmp/allow.yaml" {
		t.Errorf("trimmed path = %q", p)
	}
}

// ---- canonicaliseMethodList ----------------------------------

func TestCanonicaliseMethodList(t *testing.T) {
	in := []string{"invite", "REGISTER", "invite", " ", ""}
	out := canonicaliseMethodList(in)
	if len(out) != 2 {
		t.Fatalf("got %v, want 2 unique entries", out)
	}
	if out[0] != "INVITE" || out[1] != "REGISTER" {
		t.Errorf("sorted = %v, want [INVITE, REGISTER]", out)
	}
}
