package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/codesys/wire"
)

func TestBuildHelloMagic(t *testing.T) {
	t.Parallel()
	got := wire.BuildHello()
	want := []byte{0xCD, 0xCD, 0xCD, 0xCD}
	if !bytes.Equal(got, want) {
		t.Fatalf("hello magic: got %x want %x", got, want)
	}
}

func TestClassifyMagicPrefix(t *testing.T) {
	t.Parallel()
	resp := append([]byte{0xCD, 0xCD, 0xCD, 0xCD, 0x00, 0x00, 0x00, 0x10}, make([]byte, 16)...)
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if note != "BlockDriver magic" {
		t.Fatalf("note: got %q", note)
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
			name: "CoDeSys mixed-case",
			in:   []byte("\x00\x00\x00\x00CoDeSys V3.5 SP19\n"),
			want: "banner=CoDeSys",
		},
		{
			name: "CODESYS uppercase",
			in:   []byte("\x00\x00\x00\x00CODESYS Runtime Toolkit\n"),
			want: "banner=CODESYS",
		},
		{
			name: "3S-Smart in middle",
			in:   bytes.Repeat([]byte("\x01"), 32), /*spacer*/
			want: "banner=3S-Smart",
		},
		{
			name: "CmpHostname substring",
			in:   []byte("\x00\x01\x02\x03 unknown-component CmpHostname=PLC42 \r\n"),
			want: "banner=CmpHostname",
		},
	}
	cases[2].in = append(cases[2].in, []byte("3S-Smart Software Solutions GmbH")...)
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

func TestClassifyNotCoDeSys(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		[]byte("HTTP/1.1 200 OK\r\n\r\n<html>"),
		[]byte("\x05\x00\x00\x00 SSH-2.0-OpenSSH_9.3"),
		[]byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 some other binary"),
		bytes.Repeat([]byte("\xAB"), 32),
	}
	for i, in := range cases {
		_, err := wire.Classify(in)
		if !errors.Is(err, wire.ErrNotCoDeSys) {
			t.Fatalf("case %d: expected ErrNotCoDeSys, got %v", i, err)
		}
	}
}

func TestIsBlockDriverFrame(t *testing.T) {
	t.Parallel()
	if !wire.IsBlockDriverFrame([]byte{0xCD, 0xCD, 0xCD, 0xCD, 0x00}) {
		t.Fatalf("expected true on magic-prefixed buf")
	}
	if wire.IsBlockDriverFrame([]byte{0xCD, 0xCD, 0xCD}) {
		t.Fatalf("3-byte buf should be too short")
	}
	if wire.IsBlockDriverFrame(nil) {
		t.Fatalf("nil should be false")
	}
	if wire.IsBlockDriverFrame([]byte{0x00, 0xCD, 0xCD, 0xCD, 0xCD}) {
		t.Fatalf("magic must be the prefix, not embedded")
	}
}
