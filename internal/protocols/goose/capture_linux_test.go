//go:build linux

package goose

import "testing"

func TestHtons(t *testing.T) {
	if got := htons(0x0003); got != 0x0300 {
		t.Fatalf("htons(0x0003) = 0x%04x, want 0x0300", got)
	}
	if got := htons(0x88b8); got != 0xb888 {
		t.Fatalf("htons(0x88b8) = 0x%04x, want 0xb888", got)
	}
}

func TestOpenLiveCapture_BadInterface(t *testing.T) {
	// A non-existent interface must error cleanly (net.InterfaceByName
	// fails before any privileged socket call), never panic.
	if _, err := OpenLiveCapture("nonexistent-elsereno-test-iface-999"); err == nil {
		t.Fatal("expected an error for a bogus interface name")
	}
}
