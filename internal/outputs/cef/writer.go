// Package cef emits Common Event Format messages (ArcSight CEF 0.1).
//
// CEF layout per ArcSight documentation:
//
//	CEF:Version|Vendor|Product|ProductVersion|SignatureID|Name|Severity|Extension
//
// ElSereno emits one line per Finding. Severity is the CEF 1..10
// scale derived from the Finding score.
package cef

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"local/elsereno/internal/core"
)

// Contract is the schema identifier for CEF v1 output.
const Contract = "cef:v1"

// Vendor / Product / ProductVersion are CEF envelope fields. Version
// follows the binary's release — callers set it via WithVersion.
const (
	Vendor  = "ElSereno"
	Product = "elsereno"
)

// Writer streams findings to an io.Writer in CEF format.
type Writer struct {
	w       io.Writer
	version string
}

// NewWriter constructs a Writer. version becomes the ProductVersion
// field; "dev" is the default when unset.
func NewWriter(w io.Writer, version string) *Writer {
	if version == "" {
		version = "dev"
	}
	return &Writer{w: w, version: version}
}

// WriteFinding serialises f as a single CEF line terminated by a
// newline. addr is the target's host:port for correlation.
func (x *Writer) WriteFinding(f core.Finding, addr string) error {
	if f.ID == "" {
		return fmt.Errorf("cef: finding.ID is required")
	}
	// Core envelope — pipes separate header fields and therefore
	// must be escaped in each field.
	header := fmt.Sprintf(
		"CEF:0|%s|%s|%s|%s|%s|%d|",
		escapeHeader(Vendor),
		escapeHeader(Product),
		escapeHeader(x.version),
		escapeHeader(f.Protocol),
		escapeHeader(fmt.Sprintf("%s probe", f.Protocol)),
		cefSeverity(f.Score),
	)
	ext := buildExtensions(f, addr)
	_, err := io.WriteString(x.w, header+ext+"\n")
	return err
}

// cefSeverity maps a 0-100 score to CEF's 1..10 severity scale.
// Anything below 10 is "very low" (1), 10-19 is 2, ... 90-100 is 10.
func cefSeverity(score int) int {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	s := score / 10
	if s < 1 {
		s = 1
	}
	if s > 10 {
		s = 10
	}
	return s
}

// buildExtensions renders the space-separated key=value tail. Keys
// are emitted in alphabetical order for deterministic output (helps
// diff-based tests).
func buildExtensions(f core.Finding, addr string) string {
	pairs := map[string]string{
		"dst":             addr,
		"deviceProduct":   Product,
		"externalId":      string(f.ID),
		"cat":             "protocol-probe",
		"cs1Label":        "protocol",
		"cs1":             f.Protocol,
		"cs2Label":        "severity",
		"cs2":             string(f.Severity),
		"cn1Label":        "score",
		"cn1":             fmt.Sprintf("%d", f.Score),
		"rt":              f.CreatedAt.UTC().Format("Jan 02 2006 15:04:05 MST"),
		"elseRunId":       string(f.RunID),
		"elseFindingHash": fmt.Sprintf("%x", f.FindingHash),
	}
	for k, v := range f.Factors {
		pairs["elseFactor_"+k] = fmt.Sprintf("%d", v)
	}
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
		b.WriteByte('=')
		b.WriteString(escapeExtension(pairs[k]))
	}
	return b.String()
}

// escapeHeader escapes backslashes and pipes in a CEF header field.
func escapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// escapeExtension escapes backslash, equals, and newline in an
// extension value. Spaces are allowed inside values only when
// escaped; our values are single-token enough that we pass them
// through verbatim.
func escapeExtension(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
