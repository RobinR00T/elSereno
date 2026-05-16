package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/gesrtp/wire"
)

func TestBuildConnectionInitLayout(t *testing.T) {
	t.Parallel()
	got := wire.BuildConnectionInit()
	if len(got) != 56 {
		t.Fatalf("frame length: got %d want 56", len(got))
	}
	if got[0] != 0x02 {
		t.Fatalf("type byte: got 0x%02x want 0x02", got[0])
	}
	for i := 1; i < len(got); i++ {
		if got[i] != 0x00 {
			t.Fatalf("byte %d: got 0x%02x want 0x00", i, got[i])
		}
	}
}

func TestClassifyResponseHappyPath(t *testing.T) {
	t.Parallel()
	resp := make([]byte, 56)
	resp[0] = 0x03
	if err := wire.ClassifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClassifyResponseShortFrame(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 27, 55} {
		err := wire.ClassifyResponse(make([]byte, n))
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestClassifyResponseWrongType(t *testing.T) {
	t.Parallel()
	for _, b := range []byte{0x00, 0x01, 0x02, 0x04, 0xFF} {
		resp := make([]byte, 56)
		resp[0] = b
		err := wire.ClassifyResponse(resp)
		if !errors.Is(err, wire.ErrNotResponse) {
			t.Fatalf("byte0=0x%02x: expected ErrNotResponse, got %v", b, err)
		}
	}
}

func TestClassifyResponseLongerThan56AcceptsPrefix(t *testing.T) {
	t.Parallel()
	// SRTP is mailbox-framed, but a TCP read could hand us extra
	// bytes from a follow-up frame. The classifier should accept
	// a response prefix as long as the first 56 bytes are valid.
	resp := make([]byte, 128)
	resp[0] = 0x03
	if err := wire.ClassifyResponse(resp); err != nil {
		t.Fatalf("unexpected error on prefixed response: %v", err)
	}
}

func TestExtractModelHintCanonicalPrefixes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "IC693 in payload",
			in:   appendBytes(make([]byte, 8), []byte("IC693CPU374\x00\x00")...),
			want: "IC693CPU374",
		},
		{
			name: "IC695 with dash",
			in:   appendBytes(make([]byte, 12), []byte("IC695CPE330-AB\x00")...),
			want: "IC695CPE330-AB",
		},
		{
			name: "PACSystems marketing string",
			in:   appendBytes(make([]byte, 16), []byte("PACSystems_RX3i\x00")...),
			want: "PACSystems_RX3i",
		},
		{
			name: "RX7i short form",
			in:   appendBytes(make([]byte, 4), []byte("RX7iCPU\x00")...),
			want: "RX7iCPU",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := wire.ExtractModelHint(c.in)
			if got != c.want {
				t.Fatalf("ExtractModelHint: got %q want %q", got, c.want)
			}
		})
	}
}

func TestExtractModelHintNoMatch(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		nil,
		make([]byte, 0),
		make([]byte, 56),                  // all zeros
		[]byte("ABCDE12345"),              // no canonical prefix
		[]byte("\x01\x02\x03IC69\x00"),    // truncated prefix (4 chars)
		[]byte("\x00\x00\x00ic693cpu374"), // lowercase doesn't start a run
		append([]byte("\x01\x02"), []byte("Modicon-PLC")...), // wrong vendor family
	}
	for i, in := range cases {
		got := wire.ExtractModelHint(in)
		if got != "" {
			t.Fatalf("case %d: expected empty string, got %q", i, got)
		}
	}
}

func TestExtractModelHintFirstWins(t *testing.T) {
	t.Parallel()
	// Two candidate prefixes — the scanner should return the
	// first one it encounters.
	in := appendBytes(make([]byte, 4), []byte("IC693CPU\x00\x00\x00IC695CPE\x00")...)
	got := wire.ExtractModelHint(in)
	if got != "IC693CPU" {
		t.Fatalf("first-wins: got %q want IC693CPU", got)
	}
}

func TestExtractModelHintStopsAtNonPrintable(t *testing.T) {
	t.Parallel()
	// Run terminates at the first non-letter / non-digit / non-
	// dash / non-underscore byte. Spaces are NOT included.
	in := []byte("\x00\x00\x00IC693CPU374 backplane\x00")
	got := wire.ExtractModelHint(in)
	if got != "IC693CPU374" {
		t.Fatalf("ExtractModelHint: got %q want IC693CPU374", got)
	}
}

func appendBytes(prefix []byte, suffix ...byte) []byte {
	return append(prefix, suffix...)
}

// TestExtractModelHint_v230Prefixes (v2.30+): the expanded
// family prefix table picks up VersaMax-M / CIMPLICITY /
// IS220 / IS215 / MarkVIe / Series-One / Series-90 / PAC-IO
// strings embedded in a 56-byte mailbox response.
func TestExtractModelHint_v230Prefixes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want string
	}{
		{"VersaMax-M07A", "VersaMax-M07A"},
		{"CIMPLICITY-HMI", "CIMPLICITY-HMI"},
		{"IS220PCAAH1A", "IS220PCAAH1A"},
		{"IS215UCVEH2A", "IS215UCVEH2A"},
		{"MarkVIe-Ctlr_05", "MarkVIe-Ctlr_05"},
		{"Series-One-2", "Series-One-2"},
		{"Series-90-30", "Series-90-30"},
		{"PAC-IO-RT01", "PAC-IO-RT01"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			buf := make([]byte, 56)
			copy(buf[20:], []byte(c.name)) // arbitrary offset
			got := wire.ExtractModelHint(buf)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestIsMailboxResponseTrueOnly(t *testing.T) {
	t.Parallel()
	resp := make([]byte, 56)
	resp[0] = 0x03
	if !wire.IsMailboxResponse(resp) {
		t.Fatalf("expected true on a 56-byte 0x03 prefix")
	}
	req := wire.BuildConnectionInit()
	if wire.IsMailboxResponse(req) {
		t.Fatalf("expected false on a request frame")
	}
	if wire.IsMailboxResponse(nil) {
		t.Fatalf("nil should not be a mailbox response")
	}
	if wire.IsMailboxResponse([]byte{0x03}) {
		t.Fatalf("single byte too short to be a mailbox response")
	}
	short := make([]byte, 55)
	short[0] = 0x03
	if wire.IsMailboxResponse(short) {
		t.Fatalf("55-byte buffer too short")
	}
}
