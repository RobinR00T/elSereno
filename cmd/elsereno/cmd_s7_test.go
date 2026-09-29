package main

import (
	"bytes"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/s7"
)

func TestS7ProbeProtectionRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newS7ProbeProtectionCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}

func TestS7ProbeIdentityRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newS7ProbeIdentityCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}

func TestS7ProbeRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newS7ProbeCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}

func TestEmitS7JSON_PostureKeys(t *testing.T) {
	t.Parallel()
	res := s7.PostureResult{
		IsS7: true, SetupOK: true,
		OrderNumber: "6ES7 151-8AB01-0AB0", Firmware: "V3.2.6",
		ProtectionRead: true, Exposed: true,
	}
	res.Protection.RealLevel = 1
	res.Protection.ModeSelector = 2

	var buf bytes.Buffer
	cmd := newS7ProbeCmd()
	cmd.SetOut(&buf)
	if err := emitS7JSON(cmd, res); err != nil {
		t.Fatalf("emitS7JSON: %v", err)
	}
	out := buf.String()
	for _, key := range []string{
		`"is_s7"`, `"setup_ok"`, `"order_number"`, `"firmware"`,
		`"protection_read"`, `"exposed"`, `"real_level"`, `"mode_selector"`,
	} {
		if !strings.Contains(out, key) {
			t.Errorf("JSON missing key %s\n%s", key, out)
		}
	}
}
