package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/redlion/wire"
)

func TestBuildHelloShape(t *testing.T) {
	t.Parallel()
	got := wire.BuildHello()
	want := []byte{0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("hello: got %x want %x", got, want)
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
