package telemetry_test

import (
	"bytes"
	"strings"
	"testing"

	"local/elsereno/internal/telemetry"
)

func TestRedactLine_KeyedSecrets(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: fake secrets, the point of the test
		`X-Key: abcDEF123456ghiJKL789mno`:       "abcDEF123456ghiJKL789mno",
		`API-KEY=zoomeyeTokenValue000111222`:    "zoomeyeTokenValue000111222",
		`password: "hunter2hunter2hunter2"`:     "hunter2hunter2hunter2",
		`Authorization: Bearer tok_live_ABCdef`: "tok_live_ABCdef",
	}
	for line, secret := range cases {
		got := telemetry.RedactLine(line)
		if strings.Contains(got, secret) {
			t.Errorf("secret survived:\n in:  %s\n out: %s", line, got)
		}
		if !strings.Contains(got, telemetry.RedactedPlaceholder) {
			t.Errorf("no placeholder in: %s", got)
		}
	}
}

func TestRedactLine_BareHighEntropyToken(t *testing.T) {
	secret := "Zx9Qa2Lm8Pv3Wr7Yt1Kd5Nf0Bc4Hg6" //nolint:gosec // G101: a fake high-entropy token
	got := telemetry.RedactLine("serve: unexpected value " + secret + " seen")
	if strings.Contains(got, secret) {
		t.Fatalf("bare token survived: %s", got)
	}
}

func TestRedactLine_KeepsCleanText(t *testing.T) {
	line := "elsereno serve: listening on 127.0.0.1:8787\n"
	if got := telemetry.RedactLine(line); got != line {
		t.Fatalf("clean line changed:\n in:  %q\n out: %q", line, got)
	}
	// A UUID (a run id) must survive.
	uid := "123e4567-e89b-12d3-a456-426614174000"
	if got := telemetry.RedactLine("run " + uid); strings.Contains(got, telemetry.RedactedPlaceholder) {
		t.Fatalf("UUID redacted: %s", got)
	}
}

func TestRedactWriter_Write(t *testing.T) {
	var buf bytes.Buffer
	w := telemetry.NewRedactWriter(&buf)
	in := "serve: api_key=supersecretvalue012345 failed\n"
	n, err := w.Write([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(in) {
		t.Fatalf("Write reported %d, want %d (an io.Writer reports the input length)", n, len(in))
	}
	if strings.Contains(buf.String(), "supersecretvalue012345") {
		t.Fatalf("secret reached the sink: %s", buf.String())
	}
}
