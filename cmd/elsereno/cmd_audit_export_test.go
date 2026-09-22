package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/audit"
)

func sampleEntry(id int64, et audit.EventType, payload string) audit.Entry {
	return audit.Entry{
		ID:         id,
		OccurredAt: time.Date(2026, 9, 22, 20, 0, 0, 0, time.UTC),
		Actor:      "tester",
		EventType:  et,
		Payload:    json.RawMessage(payload),
	}
}

func TestAuditToCEF(t *testing.T) {
	t.Parallel()
	e := sampleEntry(7, audit.EventDNP3IINAlert,
		`{"kind":"state_change","bits":["device_restart"],"src":1,"dest":2}`)
	got := auditToCEF(e)
	for _, want := range []string{
		"CEF:0|ElSereno|elsereno|dev|dnp3_iin_alert|dnp3_iin_alert|9|",
		"cs1=dnp3_iin_alert",
		"else_kind=state_change",
		`else_bits=["device_restart"]`,
		"externalId=7",
		"suser=tester",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("CEF missing %q in:\n%s", want, got)
		}
	}
}

func TestAuditToSyslog(t *testing.T) {
	t.Parallel()
	e := sampleEntry(7, audit.EventDNP3IINAlert, `{"kind":"error_burst","error_run":3}`)
	got := auditToSyslog(e)
	// facility 17 * 8 + err(3) = 139
	for _, want := range []string{
		"<139>1 2026-09-22T20:00:00.000000Z - elsereno - 7 [elsereno@32473 ",
		`event_type="dnp3_iin_alert"`,
		`kind="error_burst"`,
		`error_run="3"`,
		"] dnp3_iin_alert",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("syslog missing %q in:\n%s", want, got)
		}
	}
}

func TestAuditToSyslog_RoutineIsInfo(t *testing.T) {
	t.Parallel()
	// serve_start is tier 0 -> info(6): pri = 17*8+6 = 142.
	got := auditToSyslog(sampleEntry(1, audit.EventServeStart, `{}`))
	if !strings.HasPrefix(got, "<142>1 ") {
		t.Fatalf("routine event PRI wrong: %s", got)
	}
}

func TestRunAuditExport_FilterAndFormat(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	lines := [][]byte{}
	for _, e := range []audit.Entry{
		sampleEntry(1, audit.EventServeStart, `{}`),
		sampleEntry(2, audit.EventDNP3IINAlert, `{"kind":"state_change","bits":["device_restart"]}`),
		sampleEntry(3, audit.EventProtoProbe, `{"protocol":"dnp3"}`),
	} {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, b)
	}
	if err := os.WriteFile(path, bytes.Join(append(lines, nil), []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newAuditExportCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--path", path, "--event-type", "dnp3_iin_alert", "--format", "cef"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if strings.Count(out, "\n") != 0 {
		t.Fatalf("expected exactly one line, got:\n%s", out)
	}
	if !strings.Contains(out, "CEF:0|ElSereno|elsereno|dev|dnp3_iin_alert|") {
		t.Fatalf("wrong CEF line: %s", out)
	}
	if strings.Contains(out, "serve_start") || strings.Contains(out, "protocol_probe") {
		t.Fatalf("filter leaked other event types: %s", out)
	}
}

func TestRunAuditExport_BadFormat(t *testing.T) {
	t.Parallel()
	cmd := newAuditExportCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--format", "xml"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
