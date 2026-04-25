package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTriageCmd_ReportsAllFourBuckets — `elsereno triage` should
// emit per-bucket counts including the v1.13-chunk-6 utility row.
// Drives via NDJSON input on disk so the parsing path runs end-
// to-end.
func TestTriageCmd_ReportsAllFourBuckets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.ndjson")
	body := strings.Join([]string{
		// quick_win: critical + auth_state=0
		`{"address":"10.0.0.1","port":502,"protocol":"modbus","severity":"critical","score":95,"factors":{"auth_state":0,"impact_class":80}}`,
		// strategic: critical + impact_class=80, auth_state high
		`{"address":"10.0.0.2","port":502,"protocol":"modbus","severity":"critical","score":85,"factors":{"auth_state":80,"impact_class":80}}`,
		// utility: banner-info plugin, info severity
		`{"address":"10.0.0.3","port":80,"protocol":"banner","severity":"info","score":10,"factors":{}}`,
		// utility: low severity, no impact factor
		`{"address":"10.0.0.4","port":102,"protocol":"s7","severity":"low","score":25,"factors":{}}`,
		// routine: low severity with non-trivial impact_class
		`{"address":"10.0.0.5","port":102,"protocol":"s7","severity":"low","score":35,"factors":{"impact_class":40}}`,
		// routine: medium severity, no impact
		`{"address":"10.0.0.6","port":102,"protocol":"s7","severity":"medium","score":50,"factors":{}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newTriageCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--from-file", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()

	// Each bucket should appear with a count line.
	for _, want := range []string{
		"quick_win: 1",
		"strategic: 1",
		"utility:   2",
		"routine:   2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}
