package telemetry_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/telemetry"
)

func TestRedactByKeyName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		key, value string
		want       string
	}{
		{"api_key", "whatever", telemetry.RedactedPlaceholder},
		{"Shodan-API-KEY", "whatever", telemetry.RedactedPlaceholder},
		{"x-authorization", "Bearer foo", telemetry.RedactedPlaceholder},
		{"user_password", "pw", telemetry.RedactedPlaceholder},
		{"cookie", "session=abc", telemetry.RedactedPlaceholder},
		{"sort_key", "protocol", "protocol"}, // _key without api_/secret_ prefix
		{"operator", "alice", "alice"},
		{"", "", ""},
	}
	for _, c := range cases {
		got := telemetry.Redact(c.key, c.value)
		if got != c.want {
			t.Fatalf("Redact(%q, %q) = %q, want %q", c.key, c.value, got, c.want)
		}
	}
}

func TestRedactByEntropy(t *testing.T) {
	t.Parallel()
	// 32-byte random hex-ish string -> high entropy, long enough.
	randomish := "A7f9Q2pL8kR3nX5mZ0cV6bN1uY4wE8jH"
	got := telemetry.Redact("note", randomish)
	if got != telemetry.RedactedPlaceholder {
		t.Fatalf("expected redaction for high-entropy %q, got %q", randomish, got)
	}

	// UUID v4 — must NOT be redacted even though it is long.
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	got = telemetry.Redact("request_id", uuid)
	if got != uuid {
		t.Fatalf("UUID was redacted (%q -> %q); must pass through (PITF-004)", uuid, got)
	}

	// Short high-entropy value — below MinEntropyLen; pass through.
	short := "Aa1Bb2"
	got = telemetry.Redact("note", short)
	if got != short {
		t.Fatalf("short value was redacted: %q -> %q", short, got)
	}
}

func TestShannonEntropyMonotonic(t *testing.T) {
	t.Parallel()
	lowEntropy := strings.Repeat("A", 32)
	highEntropy := "A7f9Q2pL8kR3nX5mZ0cV6bN1uY4wE8jH"
	lo := telemetry.ShannonEntropy(lowEntropy)
	hi := telemetry.ShannonEntropy(highEntropy)
	if lo >= hi {
		t.Fatalf("entropy not monotonic: low=%v high=%v", lo, hi)
	}
	if lo != 0 {
		t.Fatalf("single-char string should have entropy 0, got %v", lo)
	}
}

func TestRedactPlaceholderString(t *testing.T) {
	t.Parallel()
	if telemetry.RedactedPlaceholder != "[REDACTED]" {
		t.Fatalf("RedactedPlaceholder changed from expected `[REDACTED]`")
	}
}
