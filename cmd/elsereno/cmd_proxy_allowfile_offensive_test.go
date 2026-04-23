//go:build offensive

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempYAML creates a tempfile with the given YAML body and
// returns its path. File is auto-cleaned at end of test.
func writeTempYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "allow.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write tempfile: %v", err)
	}
	return p
}

func TestLoadAllowFile_SIP(t *testing.T) {
	p := writeTempYAML(t, `
plugin: sip
target: pbx.example.com:5060
methods:
  - INVITE
  - REGISTER
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if opts.plugin != "sip" || opts.target != "pbx.example.com:5060" {
		t.Fatalf("plugin/target = %q/%q", opts.plugin, opts.target)
	}
	if len(opts.methods) != 2 || opts.methods[0] != "INVITE" {
		t.Fatalf("methods = %v, want [INVITE, REGISTER]", opts.methods)
	}
}

func TestLoadAllowFile_IAX2(t *testing.T) {
	p := writeTempYAML(t, `
plugin: iax2
target: pbx.example.com:4569
subclasses:
  - NEW
  - REGREQ
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if opts.plugin != "iax2" {
		t.Fatalf("plugin = %q", opts.plugin)
	}
	if len(opts.subclasses) != 2 {
		t.Fatalf("subclasses = %v", opts.subclasses)
	}
}

func TestLoadAllowFile_PBXHTTP(t *testing.T) {
	p := writeTempYAML(t, `
plugin: pbxhttp
target: pbx.example.com:443
allow:
  - "POST:/admin/config.php"
  - "DELETE:/admin/user/42"
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if len(opts.allowEntries) != 2 {
		t.Fatalf("allow = %v", opts.allowEntries)
	}
}

func TestLoadAllowFile_Modbus(t *testing.T) {
	p := writeTempYAML(t, `
plugin: modbus
target: plc.example.com:502
functions: [6, 16]
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if len(opts.functions) != 2 || opts.functions[0] != 6 || opts.functions[1] != 16 {
		t.Fatalf("functions = %v", opts.functions)
	}
}

func TestLoadAllowFile_OPCUA(t *testing.T) {
	p := writeTempYAML(t, `
plugin: opcua
target: plc.example.com:4840
services: [673, 704]
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if len(opts.services) != 2 {
		t.Fatalf("services = %v", opts.services)
	}
}

func TestLoadAllowFile_BACnet(t *testing.T) {
	p := writeTempYAML(t, `
plugin: bacnet
target: bms.example.com:47808
service_choices: [15, 20]
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err != nil {
		t.Fatalf("loadAllowFile: %v", err)
	}
	if len(opts.serviceChoices) != 2 {
		t.Fatalf("service_choices = %v", opts.serviceChoices)
	}
}

func TestLoadAllowFile_MissingPlugin(t *testing.T) {
	p := writeTempYAML(t, `
target: pbx:5060
methods: [INVITE]
`)
	var opts proxyListenOpts
	err := loadAllowFile(p, &opts)
	if err == nil || !strings.Contains(err.Error(), "plugin") {
		t.Fatalf("expected plugin-missing error, got %v", err)
	}
}

func TestLoadAllowFile_MissingTarget(t *testing.T) {
	p := writeTempYAML(t, `
plugin: sip
methods: [INVITE]
`)
	var opts proxyListenOpts
	err := loadAllowFile(p, &opts)
	if err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected target-missing error, got %v", err)
	}
}

func TestLoadAllowFile_UnknownPlugin(t *testing.T) {
	p := writeTempYAML(t, `
plugin: snmp
target: host:161
`)
	var opts proxyListenOpts
	err := loadAllowFile(p, &opts)
	if err == nil || !strings.Contains(err.Error(), "unsupported plugin") {
		t.Fatalf("expected unsupported-plugin error, got %v", err)
	}
}

func TestLoadAllowFile_UnknownField(t *testing.T) {
	// KnownFields(true) catches typos in the YAML.
	p := writeTempYAML(t, `
plugin: sip
target: pbx:5060
method: INVITE # typo: should be "methods"
`)
	var opts proxyListenOpts
	if err := loadAllowFile(p, &opts); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestLoadAllowFile_NonexistentFile(t *testing.T) {
	var opts proxyListenOpts
	if err := loadAllowFile("/does/not/exist.yaml", &opts); err == nil {
		t.Fatal("expected file-not-found error")
	}
}
