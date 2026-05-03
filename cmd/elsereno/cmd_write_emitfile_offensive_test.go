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
	af := buildAllowFileSIP("pbx.example.com:5060", []string{"invite", "REGISTER", "invite"}, nil, nil, nil, 0)
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
	for _, stray := range []string{"subclasses:", "allow:", "functions:", "writes:", "services:", "service_choices:"} {
		if strings.Contains(out, stray) {
			t.Errorf("unexpected field %q in sip output:\n%s", stray, out)
		}
	}
}

func TestEmitAllowFile_IAX2Stdout(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileIAX2("pbx:4569", []string{"new", "REGREQ"}, 0)
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
	af := buildAllowFilePBXHTTP("pbx:443", []string{"POST:/admin/config.php", "DELETE:/admin/user/42"}, 0)
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
	af := buildAllowFileSIP("pbx:5060", []string{"INVITE"}, nil, nil, nil, 0)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emitAllowFile: %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- `path` is a freshly-constructed test tempdir path, not untrusted input
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
	if err := emitAllowFile(cmd, path, buildAllowFileSIP("pbx:5060", []string{"INVITE", "REGISTER"}, nil, nil, nil, 0)); err != nil {
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

// TestEmitAllowFile_RoundTripSIPWithPrefixes — v1.9 chunk 5
// sanity check that to_prefixes: survives emit → load.
func TestEmitAllowFile_RoundTripSIPWithPrefixes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileSIP("pbx:5060",
		[]string{"INVITE"},
		[]string{"+34", "+44"},
		nil, nil, 0)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(opts.toPrefixes) != 2 {
		t.Errorf("toPrefixes=%v, want 2", opts.toPrefixes)
	}
}

// TestEmitAllowFile_RoundTripSIPWithAORs — v1.10 chunk 1 closes
// the REGISTER AOR allowlist round-trip: emit writes aors:,
// load materialises opts.aors back on the proxyListenOpts side.
func TestEmitAllowFile_RoundTripSIPWithAORs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	aors := []string{
		"sip:bob@pbx.internal",
		"sip:alice@pbx.internal", // unordered on purpose
	}
	af := buildAllowFileSIP("pbx:5060", []string{"REGISTER"}, nil, aors, nil, 0)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if opts.plugin != "sip" {
		t.Errorf("plugin=%q", opts.plugin)
	}
	// AORs are sorted lexicographically on emit, so after
	// round-trip they should come back sorted.
	if len(opts.aors) != 2 {
		t.Fatalf("aors=%v, want 2", opts.aors)
	}
	if opts.aors[0] != "sip:alice@pbx.internal" {
		t.Errorf("aors[0] = %q, want sip:alice@pbx.internal (sorted)", opts.aors[0])
	}
	if opts.aors[1] != "sip:bob@pbx.internal" {
		t.Errorf("aors[1] = %q, want sip:bob@pbx.internal (sorted)", opts.aors[1])
	}
}

// TestEmitAllowFile_RoundTripSIPWithPrefixesAndAORs — both
// v1.9 and v1.10 fields active at the same time; YAML contains
// both keys, both survive the round-trip.
func TestEmitAllowFile_RoundTripSIPWithPrefixesAndAORs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileSIP("pbx:5060",
		[]string{"INVITE", "REGISTER"},
		[]string{"+34"},
		[]string{"sip:alice@pbx.internal"},
		nil, 0)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(opts.methods) != 2 {
		t.Errorf("methods=%v", opts.methods)
	}
	if len(opts.toPrefixes) != 1 {
		t.Errorf("toPrefixes=%v", opts.toPrefixes)
	}
	if len(opts.aors) != 1 {
		t.Errorf("aors=%v", opts.aors)
	}
}

// TestEmitAllowFile_RoundTripCWMPWithFirmware — v1.12 chunk 10
// per-image firmware allowlist round-trips through `firmware:`
// YAML.
func TestEmitAllowFile_RoundTripCWMPWithFirmware(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)

	rpcs := []string{"Download"}
	firmware := []string{
		"url=https://acs.example.com/firmware/router-1.2.3.bin;sha256=" + strings.Repeat("a", 64),
		"url=https://acs.example.com/firmware/cpe-fw.img",
	}
	af := buildAllowFileCWMP("acs:7547", rpcs, nil, firmware)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(opts.cwmpFirmware) != 2 {
		t.Fatalf("cwmpFirmware=%v, want 2 entries", opts.cwmpFirmware)
	}
	// Sort order: alphabetic by URL. cpe-fw.img < router-1.2.3.bin.
	if !strings.Contains(opts.cwmpFirmware[0], "url=https://acs.example.com/firmware/cpe-fw.img") {
		t.Errorf("[0] = %q, want cpe-fw first", opts.cwmpFirmware[0])
	}
	if !strings.Contains(opts.cwmpFirmware[1], "router-1.2.3.bin") || !strings.Contains(opts.cwmpFirmware[1], "sha256=") {
		t.Errorf("[1] = %q, want router-1.2.3 with sha256", opts.cwmpFirmware[1])
	}
}

// TestEmitAllowFile_RoundTripBACnetWithObjects — v1.12 chunk 7
// per-object WriteProperty allowlist round-trips through the
// `objects:` YAML field.
func TestEmitAllowFile_RoundTripBACnetWithObjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)

	choices := []uint{15}
	objects := []string{
		"type=2;instance=3;property=85",
		"type=0;instance=42;property=85",
	}
	af := buildAllowFileBACnet(buildAllowFileBACnetInputs{
		Target:     "bms:47808",
		Choices:    choices,
		ObjectsRaw: objects,
	})
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(opts.bacnetObjects) != 2 {
		t.Fatalf("bacnetObjects=%v, want 2 entries", opts.bacnetObjects)
	}
	// Sort order: (type, instance, property).
	if opts.bacnetObjects[0] != "type=0;instance=42;property=85" {
		t.Errorf("bacnetObjects[0] = %q", opts.bacnetObjects[0])
	}
	if opts.bacnetObjects[1] != "type=2;instance=3;property=85" {
		t.Errorf("bacnetObjects[1] = %q", opts.bacnetObjects[1])
	}
}

// TestEmitAllowFile_RoundTripOPCUAWithCallMethods — v1.12 chunk 6
// per-CallMethod allowlist round-trips through call_methods: YAML.
func TestEmitAllowFile_RoundTripOPCUAWithCallMethods(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)

	services := []uint{704}
	callMethods := []string{
		"object=ns=2;i=100;method=ns=2;i=101",
		"object=ns=3;s=DeviceFolder;method=ns=3;s=Restart",
	}
	af := buildAllowFileOPCUA("plc:4840", services, nil, callMethods, 0)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(opts.callMethods) != 2 {
		t.Fatalf("callMethods=%v, want 2", opts.callMethods)
	}
	found := map[string]bool{}
	for _, e := range opts.callMethods {
		found[e] = true
	}
	for _, want := range []string{
		"object=ns=2;i=100;method=ns=2;i=101",
		"object=ns=3;s=DeviceFolder;method=ns=3;s=Restart",
	} {
		if !found[want] {
			t.Errorf("missing callMethods entry %q in %v", want, opts.callMethods)
		}
	}
}

// TestEmitAllowFile_RoundTripSIPWithFromDomains — v1.12 chunk 5
// closes the From-domain round-trip: emit writes `from_domains:`,
// load materialises opts.fromDomains on the proxyListenOpts side.
func TestEmitAllowFile_RoundTripSIPWithFromDomains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	// Mixed-case on purpose — emitter lowercases.
	fromDomains := []string{"VoIP.Example.com", "internal.pbx"}
	af := buildAllowFileSIP("pbx:5060", []string{"INVITE", "REGISTER"}, nil, nil, fromDomains, 0)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(opts.fromDomains) != 2 {
		t.Fatalf("fromDomains=%v, want 2 entries", opts.fromDomains)
	}
	// Sort order: lexicographic on the lowercased form.
	if opts.fromDomains[0] != "internal.pbx" {
		t.Errorf("fromDomains[0] = %q, want internal.pbx (sorted+lowered)", opts.fromDomains[0])
	}
	if opts.fromDomains[1] != "voip.example.com" {
		t.Errorf("fromDomains[1] = %q, want voip.example.com (lowered)", opts.fromDomains[1])
	}
}

// TestEmitAllowFile_SIPOmitsFromDomainsWhenEmpty — YAML doesn't
// emit the `from_domains:` key when the list is empty (preserves
// backwards-compat with v1.10 files).
func TestEmitAllowFile_SIPOmitsFromDomainsWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileSIP("pbx:5060", []string{"INVITE"}, nil, nil, nil, 0)
	if err := emitAllowFile(cmd, "-", af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "from_domains") {
		t.Errorf("from_domains: should be omitted when list empty:\n%s", out)
	}
}

// TestEmitAllowFile_SIPOmitsAORsWhenEmpty — YAML doesn't emit
// the `aors:` key when list is nil (keeps backwards compat with
// v1.9 files).
func TestEmitAllowFile_SIPOmitsAORsWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileSIP("pbx:5060", []string{"INVITE"}, nil, nil, nil, 0)
	if err := emitAllowFile(cmd, "-", af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "aors") {
		t.Errorf("aors: should be omitted when list empty:\n%s", out)
	}
	if strings.Contains(out, "to_prefixes") {
		t.Errorf("to_prefixes: should be omitted when list empty:\n%s", out)
	}
}

// TestEmitAllowFile_RoundTripCWMP — v1.11 chunk 1: RPCs
// survive emit → load, sorted + prefix-stripped.
func TestEmitAllowFile_RoundTripCWMP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	// Mix of prefixed + bare + whitespace + duplicate to
	// exercise the canonicaliser inside buildAllowFileCWMP.
	rpcs := []string{
		"cwmp:Reboot",
		"SetParameterValues",
		"  SetParameterValues  ", // duplicate after trim
		"Download",
	}
	af := buildAllowFileCWMP("acs.example.com:7547", rpcs, nil, nil)
	if err := emitAllowFile(cmd, path, af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if opts.plugin != "cwmp" {
		t.Errorf("plugin=%q, want cwmp", opts.plugin)
	}
	if len(opts.rpcs) != 3 {
		t.Fatalf("rpcs=%v, want 3 entries (dedup'd)", opts.rpcs)
	}
	if opts.rpcs[0] != "Download" {
		t.Errorf("rpcs[0]=%q, want Download (sorted)", opts.rpcs[0])
	}
	if opts.rpcs[1] != "Reboot" {
		t.Errorf("rpcs[1]=%q, want Reboot (sorted)", opts.rpcs[1])
	}
	if opts.rpcs[2] != "SetParameterValues" {
		t.Errorf("rpcs[2]=%q, want SetParameterValues (sorted)", opts.rpcs[2])
	}
}

func TestEmitAllowFile_CWMPOmitsRPCsWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileCWMP("acs:7547", nil, nil, nil)
	if err := emitAllowFile(cmd, "-", af); err != nil {
		t.Fatalf("emit: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "rpcs") {
		t.Errorf("rpcs: should be omitted when list empty:\n%s", out)
	}
}

// TestLoadAllowFile_CWMPWithRPCs — direct load test: YAML with
// rpcs: is recognised by KnownFields(true).
func TestLoadAllowFile_CWMPWithRPCs(t *testing.T) {
	p := writeTempYAML(t, `
plugin: cwmp
target: acs.example.com:7547
rpcs:
  - SetParameterValues
  - Reboot
  - FactoryReset
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if len(opts.rpcs) != 3 {
		t.Fatalf("rpcs=%v, want 3 entries", opts.rpcs)
	}
	if opts.rpcs[0] != "SetParameterValues" {
		t.Errorf("rpcs[0]=%q", opts.rpcs[0])
	}
}

// TestLoadAllowFile_SIPWithAORs — direct load test: YAML with
// aors: is recognised by the unmarshal; `KnownFields(true)`
// doesn't reject it.
func TestLoadAllowFile_SIPWithAORs(t *testing.T) {
	p := writeTempYAML(t, `
plugin: sip
target: pbx.example.com:5060
methods: [REGISTER]
aors:
  - sip:alice@pbx.example.com
  - sip:bob@pbx.example.com
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if len(opts.aors) != 2 {
		t.Fatalf("aors=%v, want 2 entries", opts.aors)
	}
	if opts.aors[0] != "sip:alice@pbx.example.com" {
		t.Errorf("aors[0] = %q", opts.aors[0])
	}
}

func TestEmitAllowFile_RoundTripPBXHTTP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	entries := []string{"POST:/admin/config.php", "DELETE:/admin/user/42"}
	if err := emitAllowFile(cmd, path, buildAllowFilePBXHTTP("pbx:443", entries, 0)); err != nil {
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
	af := buildAllowFileOPCUA("plc.example.com:4840", services, nodeIDs, nil, 0)
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

// TestEmitAllowFile_RoundTripOPCUAWithCanonicalNodeIDs — v1.12
// chunk 3 extends node_ids with the `canonical:` YAML field for
// String / Guid / ByteString encodings. Round-trip keeps the
// canonical form verbatim so the operator's token stays stable.
func TestEmitAllowFile_RoundTripOPCUAWithCanonicalNodeIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml")
	var buf bytes.Buffer
	cmd := helperCmd(&buf)

	services := []uint{673}
	// Mixed: one numeric, one string, one guid, one bytestring.
	nodeIDs := []string{
		"ns=3;i=100",
		"ns=2;s=Temperature",
		"ns=1;g=6b29fc40-ca47-1067-b31d-00dd010662da",
		"ns=4;b=DEADBEEF",
	}
	af := buildAllowFileOPCUA("plc.example.com:4840", services, nodeIDs, nil, 0)
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
	if len(opts.nodeIDs) != 4 {
		t.Fatalf("nodeIDs=%v, want 4 entries", opts.nodeIDs)
	}
	// Sort order: numeric first (by ns,id) then canonical strings
	// (lexicographic).
	wantOrder := []string{
		"ns=3;i=100",
		"ns=1;g=6B29FC40CA471067B31D00DD010662DA", // normalised to uppercase, no dashes
		"ns=2;s=Temperature",
		"ns=4;b=DEADBEEF",
	}
	if len(opts.nodeIDs) != len(wantOrder) {
		t.Fatalf("nodeIDs len mismatch: got %d, want %d", len(opts.nodeIDs), len(wantOrder))
	}
	for i, want := range wantOrder {
		if opts.nodeIDs[i] != want {
			t.Errorf("nodeIDs[%d] = %q, want %q", i, opts.nodeIDs[i], want)
		}
	}
}

func TestEmitAllowFile_OPCUAOmitsNodeIDsWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	cmd := helperCmd(&buf)
	af := buildAllowFileOPCUA("plc:4840", []uint{673}, nil, nil, 0)
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
