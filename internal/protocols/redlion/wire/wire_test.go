package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/redlion/wire"
)

// TestQueries_Reference: the two identity reads are byte for byte the
// probes of cr3-fingerprint.nse (internetofallthethings/cr3-nmap) and
// of praetorian-inc/nerva's crimsonv3 plugin (PITF-079).
func TestQueries_Reference(t *testing.T) {
	t.Parallel()
	if want := []byte{0x00, 0x04, 0x01, 0x2b, 0x1b, 0x00}; !bytes.Equal(wire.ManufacturerQuery, want) {
		t.Fatalf("manufacturer query %x, want %x", wire.ManufacturerQuery, want)
	}
	if want := []byte{0x00, 0x04, 0x01, 0x2a, 0x1a, 0x00}; !bytes.Equal(wire.ModelQuery, want) {
		t.Fatalf("model query %x, want %x", wire.ModelQuery, want)
	}
}

// cr3String builds a CR3 string response the way nerva's test server
// does: length, register, type 0x0300, the string, a NUL.
func cr3String(register uint16, s string) []byte {
	data := append([]byte(s), 0x00)
	out := make([]byte, 6, 6+len(data))
	binary.BigEndian.PutUint16(out[0:2], uint16(4+len(data))) // #nosec G115 -- test strings are short.
	binary.BigEndian.PutUint16(out[2:4], register)
	out[4] = 0x03
	return append(out, data...)
}

func TestParseStringResponse(t *testing.T) {
	t.Parallel()
	got, err := wire.ParseStringResponse(cr3String(0x012b, "Red Lion Controls"))
	if err != nil || got != "Red Lion Controls" {
		t.Fatalf("manufacturer: %q, %v", got, err)
	}
	if note, err := wire.Classify(cr3String(0x012b, "Red Lion Controls")); err != nil || note != "manufacturer=Red Lion Controls" {
		t.Fatalf("Classify: %q, %v", note, err)
	}
	if got, err := wire.ParseStringResponse(append(cr3String(0x012a, "G310C2"), 0xAA)); err != nil || got != "G310C2" {
		t.Fatalf("model with trailing bytes: %q, %v", got, err)
	}
	for name, b := range map[string][]byte{
		"reflected query":   wire.ManufacturerQuery,
		"truncated frame":   cr3String(0x012b, "Red Lion Controls")[:10],
		"no data":           {0x00, 0x05, 0x01, 0x2b, 0x03, 0x00, 0x00},
		"binary data":       {0x00, 0x06, 0x01, 0x2b, 0x03, 0x00, 0x05, 0x1a},
		"too short":         {0x00, 0x04, 0x01},
		"length below head": {0x00, 0x01, 0x01, 0x2b, 0x03, 0x00, 'A'},
	} {
		if _, err := wire.ParseStringResponse(b); err == nil {
			t.Errorf("%s: parsed as a CR3 string", name)
		}
	}
}

func TestClassifyBannerSubstrings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "Red Lion Controls full",
			in:   []byte("\x00\x00\x00\x00 Red Lion Controls G3 HMI Crimson 3.1\r\n"),
			want: "banner=Red Lion Controls",
		},
		{
			name: "Crimson 3",
			in:   []byte("\x00 Welcome to Crimson 3 SP18 \r\n"),
			want: "banner=Crimson 3",
		},
		{
			name: "FlexEdge embedded",
			in:   []byte("device=FlexEdge-CORE-RTC fw=20240115\n"),
			want: "banner=FlexEdge",
		},
		{
			name: "Sixnet legacy",
			in:   []byte("\x00\x00 Sixnet RTU-IPm-310 \n"),
			want: "banner=Sixnet",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			note, err := wire.Classify(c.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if note != c.want {
				t.Fatalf("note: got %q want %q", note, c.want)
			}
		})
	}
}

func TestClassifyShortFrame(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 2, 3} {
		_, err := wire.Classify(make([]byte, n))
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestClassifyNotRedLion(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\n\r\n<html>"),
		[]byte("\x05\x00\x00\x00 SSH-2.0-OpenSSH_9.3"),
		[]byte("Server: nginx/1.25.4\r\n\r\nplaintext"),
		bytes.Repeat([]byte("\xAB"), 32),
	}
	for i, in := range cases {
		_, err := wire.Classify(in)
		if !errors.Is(err, wire.ErrNotRedLion) {
			t.Fatalf("case %d: expected ErrNotRedLion, got %v", i, err)
		}
	}
}

func TestIsRedLionBanner(t *testing.T) {
	t.Parallel()
	if !wire.IsRedLionBanner([]byte("\x00\x00 Crimson 3 SP18 \n")) {
		t.Fatalf("expected true on Crimson banner")
	}
	if wire.IsRedLionBanner(nil) {
		t.Fatalf("nil should be false")
	}
	if wire.IsRedLionBanner([]byte("HTTP/1.1 200 OK")) {
		t.Fatalf("plain HTTP should not match")
	}
}

func TestClassifyMostSpecificFirst(t *testing.T) {
	t.Parallel()
	// "Red Lion Controls" should match before "Red Lion" because
	// of ordering in RedLionBannerSubstrings.
	note, err := wire.Classify([]byte("\x00\x00 Red Lion Controls G3 \n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if note != "banner=Red Lion Controls" {
		t.Fatalf("note: got %q want banner=Red Lion Controls", note)
	}
}
