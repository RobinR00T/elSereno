package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/core"
)

// SIEM envelope identity. These mirror internal/outputs/cef and
// internal/outputs/syslog (the findings sinks) so audit events and
// findings share a vendor/product identity in the SOC. The private
// SD-ID uses the IANA private-use enterprise number 32473.
const (
	auditSIEMVendor  = "ElSereno"
	auditSIEMProduct = "elsereno"
	auditSyslogSDID  = "elsereno@32473"
	auditSyslogFac   = 17 // local1, conventional for security/audit
)

// newAuditExportCmd exports audit-chain events in SIEM-ready formats.
func newAuditExportCmd() *cobra.Command {
	var (
		path, eventType, format string
		since                   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit-chain events for a SIEM (ndjson / cef / syslog)",
		Long: `Reads the file-backed audit chain and writes each entry to stdout in
the chosen format, ready to pipe into a SIEM collector. Filter with
--event-type (e.g. dnp3_iin_alert, the DNP3 response-path detection)
and --since (e.g. 24h).

This does NOT verify the hash chain (use 'audit verify-file' for that)
and needs no vault: it reformats the recorded entries. 'cef' emits
ArcSight CEF:0 lines, 'syslog' emits RFC 5424 frames, 'ndjson' passes
each JSON record through. Example:

  elsereno audit export --event-type dnp3_iin_alert --format cef | logger`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditExport(cmd, path, eventType, format, since)
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "audit log path (default ~/.elsereno/audit.jsonl)")
	cmd.Flags().StringVar(&eventType, "event-type", "", "only export this event_type (e.g. dnp3_iin_alert); empty = all")
	cmd.Flags().StringVar(&format, "format", "ndjson", "output format: ndjson | cef | syslog")
	cmd.Flags().DurationVar(&since, "since", 0, "only export entries newer than this (e.g. 24h); 0 = all")
	return cmd
}

func runAuditExport(cmd *cobra.Command, path, eventType, format string, since time.Duration) error {
	switch format {
	case "ndjson", "cef", "syslog":
	default:
		return fail(core.ExitUsage, fmt.Errorf("--format %q: want ndjson, cef, or syslog", format))
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fail(core.ExitOSErr, err)
		}
		path = filepath.Join(home, ".elsereno", "audit.jsonl")
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied audit log path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cmd.PrintErrf("no audit log at %s (nothing to export)\n", path)
			return nil
		}
		return fail(core.ExitIOErr, err)
	}
	defer func() { _ = f.Close() }()

	var cutoff time.Time
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}
	if err := exportAuditStream(cmd.OutOrStdout(), f, eventType, format, cutoff); err != nil {
		return fail(core.ExitIOErr, err)
	}
	return nil
}

// exportAuditStream scans the JSONL audit stream, applies the
// event-type and cutoff filters, and writes each surviving entry to out
// in the chosen format.
func exportAuditStream(out io.Writer, r io.Reader, eventType, format string, cutoff time.Time) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("parse line: %w", err)
		}
		if eventType != "" && string(e.EventType) != eventType {
			continue
		}
		if !cutoff.IsZero() && e.OccurredAt.Before(cutoff) {
			continue
		}
		if _, err := io.WriteString(out, renderAuditEntry(format, e, line)+"\n"); err != nil {
			return err
		}
	}
	return sc.Err()
}

// renderAuditEntry formats one entry. `raw` is the verbatim JSONL line,
// reused as-is for ndjson so the exact record survives.
func renderAuditEntry(format string, e audit.Entry, raw []byte) string {
	switch format {
	case "cef":
		return auditToCEF(e)
	case "syslog":
		return auditToSyslog(e)
	default:
		return string(raw)
	}
}

// auditTier maps an event_type to a coarse severity tier (0 info ..
// 3 high). Detections and offensive deliveries are high; credential /
// admin / chain-management events are notable; the rest are routine.
func auditTier(t audit.EventType) int {
	switch t {
	case audit.EventDNP3IINAlert, audit.EventOffWrite, audit.EventOffDial,
		audit.EventOffSMS, audit.EventOffHarvest, audit.EventCWMPFirmwareVerify:
		return 3
	case audit.EventProxyAllowlistReload, audit.EventOffSandbox, audit.EventAdmin,
		audit.EventTokenReveal, audit.EventCredsReveal, audit.EventPurge,
		audit.EventChainRebase:
		return 2
	case audit.EventVaultUnlock, audit.EventVaultLock, audit.EventTokenRotate,
		audit.EventCredsStore, audit.EventCredsRotate, audit.EventCredsPurge:
		return 1
	default:
		return 0
	}
}

// auditToCEF renders an entry as an ArcSight CEF:0 line.
func auditToCEF(e audit.Entry) string {
	cefSev := []int{2, 4, 6, 9}[auditTier(e.EventType)] // 1..10 scale
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|",
		cefHeaderEsc(auditSIEMVendor), cefHeaderEsc(auditSIEMProduct), cefHeaderEsc("dev"),
		cefHeaderEsc(string(e.EventType)), cefHeaderEsc(string(e.EventType)), cefSev)
	pairs := map[string]string{
		"externalId": fmt.Sprintf("%d", e.ID),
		"rt":         e.OccurredAt.UTC().Format("Jan 02 2006 15:04:05 MST"),
		"suser":      e.Actor,
		"cat":        "audit",
		"cs1Label":   "event_type",
		"cs1":        string(e.EventType),
	}
	for k, v := range flattenPayload(e.Payload) {
		pairs["else_"+k] = v
	}
	return header + joinPairs(pairs, "=", cefExtEsc)
}

// auditToSyslog renders an entry as an RFC 5424 frame.
func auditToSyslog(e audit.Entry) string {
	pri := auditSyslogFac*8 + []int{6, 5, 4, 3}[auditTier(e.EventType)] // info/notice/warning/err
	ts := e.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000Z")
	params := map[string]string{
		"actor":      e.Actor,
		"event_type": string(e.EventType),
	}
	for k, v := range flattenPayload(e.Payload) {
		params[k] = v
	}
	sd := joinSD(params)
	return fmt.Sprintf("<%d>1 %s - %s - %d [%s %s] %s",
		pri, ts, auditSIEMProduct, e.ID, auditSyslogSDID, sd, string(e.EventType))
}

// flattenPayload turns the JSONB payload into deterministic string
// key=value pairs. Scalars pass through; objects/arrays are compact
// JSON. A non-object payload becomes a single "payload" key.
func flattenPayload(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		out["payload"] = strings.TrimSpace(string(raw))
		return out
	}
	for k, v := range m {
		out[k] = scalarOrJSON(v)
	}
	return out
}

// scalarOrJSON renders a JSON value as its bare scalar (string without
// quotes, number/bool verbatim) or compact JSON for objects/arrays.
func scalarOrJSON(v json.RawMessage) string {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(v))
}

// joinPairs renders a sorted key<sep>esc(value) list separated by
// spaces (CEF extension style).
func joinPairs(pairs map[string]string, sep string, esc func(string) string) string {
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteString(sep)
		b.WriteString(esc(pairs[k]))
	}
	return b.String()
}

// joinSD renders the RFC 5424 structured-data parameter list
// (key="esc(value)" space-separated, sorted).
func joinSD(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(sdEsc(params[k]))
		b.WriteByte('"')
	}
	return b.String()
}

func cefHeaderEsc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `|`, `\|`)
}

func cefExtEsc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

func sdEsc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return strings.ReplaceAll(s, `]`, `\]`)
}
