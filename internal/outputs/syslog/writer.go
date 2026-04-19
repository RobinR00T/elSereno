// Package syslog emits RFC 5424 messages. One Finding → one syslog
// frame. Structured-data parameters carry the ElSereno-specific
// fields (score, factors, finding hash) under a private SD-ID.
package syslog

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"local/elsereno/internal/core"
)

// Contract is the schema identifier for syslog v1 output.
const Contract = "syslog:v1"

// Facility is the syslog facility number. local1 (17) is conventional
// for security / audit pipelines.
const Facility = 17

// sdID is the ElSereno structured-data identifier. RFC 5424 §6.3.2
// says private SD-IDs must carry "@<enterprise-number>"; we use the
// IANA-reserved private-use range 32473.
const sdID = "elsereno@32473"

// Writer streams findings to an io.Writer in RFC 5424 frames.
type Writer struct {
	w        io.Writer
	hostname string
	app      string
	version  string
}

// NewWriter constructs a Writer. hostname, app, and version populate
// the RFC 5424 header; empty strings default to "-".
func NewWriter(w io.Writer, hostname, app, version string) *Writer {
	if hostname == "" {
		hostname = "-"
	}
	if app == "" {
		app = "elsereno"
	}
	if version == "" {
		version = "dev"
	}
	return &Writer{w: w, hostname: hostname, app: app, version: version}
}

// WriteFinding serialises f as a single RFC 5424 message.
func (x *Writer) WriteFinding(f core.Finding, addr string) error {
	if f.ID == "" {
		return fmt.Errorf("syslog: finding.ID is required")
	}
	pri := Facility*8 + severityToPRI(f.Severity)
	ts := f.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z")
	sd := buildSD(f, addr, x.version)
	msg := fmt.Sprintf("%s probe %s score=%d severity=%s",
		f.Protocol, addr, f.Score, f.Severity)
	frame := fmt.Sprintf("<%d>1 %s %s %s - %s [%s %s] %s\n",
		pri, ts, x.hostname, x.app, string(f.ID), sdID, sd, msg)
	_, err := io.WriteString(x.w, frame)
	return err
}

// severityToPRI maps ElSereno Severity to the RFC 5424 severity
// code (0=emerg .. 7=debug). We use:
//
//	critical -> 2 (crit)
//	high     -> 3 (err)
//	medium   -> 4 (warning)
//	low      -> 6 (info)
//	info     -> 7 (debug)
//
// Unknown severities fall through as notice (5).
func severityToPRI(s core.Severity) int {
	switch strings.ToLower(string(s)) {
	case "critical":
		return 2
	case "high":
		return 3
	case "medium":
		return 4
	case "low":
		return 6
	case "info", "informational":
		return 7
	default:
		return 5
	}
}

// buildSD emits the structured-data parameter portion (space-
// separated key="value" inside the brackets). Keys are ordered
// alphabetically for deterministic output.
func buildSD(f core.Finding, addr, version string) string {
	params := map[string]string{
		"addr":        addr,
		"protocol":    f.Protocol,
		"severity":    string(f.Severity),
		"score":       fmt.Sprintf("%d", f.Score),
		"runId":       string(f.RunID),
		"findingHash": fmt.Sprintf("%x", f.FindingHash),
		"schema":      Contract,
		"version":     version,
	}
	for k, v := range f.Factors {
		params["factor_"+k] = fmt.Sprintf("%d", v)
	}
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
		b.WriteString(escapeSD(params[k]))
		b.WriteByte('"')
	}
	return b.String()
}

// escapeSD escapes the three characters the spec calls out: quote,
// backslash, and close-bracket.
func escapeSD(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}
