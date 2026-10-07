package atmodem

import (
	"bytes"
	"strings"
	"testing"
)

// TestForwardAndFilter_RefusalAnswersError: a forbidden command (ATD,
// dial) never reaches the modem and the client is told ERROR; an allowed
// one passes. Until 2026-10-07 the refusal wrote nothing to the client.
func TestForwardAndFilter_RefusalAnswersError(t *testing.T) {
	t.Parallel()
	var upstream, client bytes.Buffer
	in := strings.NewReader("ATD5551234\rATI\r")
	_ = forwardAndFilter(in, &upstream, &client)
	if strings.Contains(upstream.String(), "ATD") {
		t.Fatalf("the dial command reached the modem: %q", upstream.String())
	}
	if !strings.Contains(upstream.String(), "ATI") {
		t.Fatalf("the allowed command did not pass: %q", upstream.String())
	}
	if client.String() != "ERROR\r\n" {
		t.Fatalf("client got %q, want ERROR", client.String())
	}
}
