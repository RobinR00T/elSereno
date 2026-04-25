package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scoring"
)

// newExplainCmd prints the scoring-factor breakdown for a single
// finding. Input is a JSON document on stdin (or `--from-file`) with
// the `factors` map and optional `protocol`/`severity` hints — exactly
// the shape the NDJSON output emits.
func newExplainCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain how a finding's score was computed",
		Long: "explain reads a finding (NDJSON v1 shape) from --from-file or stdin " +
			"and prints each factor's contribution alongside the derived severity.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var raw []byte
			var err error
			if path != "" {
				// #nosec G304 -- caller-supplied path
				raw, err = os.ReadFile(path)
				if err != nil {
					return fail(core.ExitIOErr, err)
				}
			} else {
				raw, err = readAll(os.Stdin)
				if err != nil {
					return fail(core.ExitIOErr, err)
				}
			}
			return explainFromJSON(cmd, raw)
		},
	}
	cmd.Flags().StringVar(&path, "from-file", "", "read NDJSON finding from this file (default: stdin)")
	return cmd
}

func explainFromJSON(cmd *cobra.Command, raw []byte) error {
	if len(raw) == 0 {
		return fail(core.ExitNoInput, fmt.Errorf("empty input"))
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fail(core.ExitDataErr, err)
	}
	factors, ok := doc["factors"].(map[string]any)
	if !ok {
		return fail(core.ExitDataErr, fmt.Errorf("missing `factors` map"))
	}
	w, err := scoring.LoadDefaults()
	if err != nil {
		return fail(core.ExitSoftware, err)
	}

	keys := make([]string, 0, len(factors))
	for k := range factors {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	cmd.Println("Factor breakdown:")
	cmd.Printf("  %-14s  %-6s  %-6s  %-10s\n", "factor", "sub", "weight", "contrib")
	intFactors := make(map[string]int, len(factors))
	for _, k := range keys {
		n, _ := factors[k].(float64)
		intFactors[k] = int(n)
		weight, known := w.Values[k]
		status := "known"
		if !known {
			status = "unknown"
			weight = 0
		}
		cmd.Printf("  %-14s  %-6d  %-6.2f  %-10.2f  (%s)\n",
			k, int(n), weight, float64(int(n))*weight, status)
	}
	score, sev, err := scoring.Score(w, intFactors)
	if err != nil {
		cmd.Println("(score recomputation failed:", err, ")")
	} else {
		cmd.Printf("\nrecomputed: score=%d severity=%s\n", score, sev)
	}
	if sevHint, ok := doc["severity"].(string); ok {
		cmd.Printf("stored severity: %s\n", sevHint)
	}
	return nil
}

// newWhyCmd is `elsereno why <target>`. It prints the available scope
// context and the default scoring weights — answering "why is this
// target (or might this target) be flagged the way it is" without
// needing a live DB.
func newWhyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "why <address:port>",
		Short: "Explain the scoring posture for a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := scoring.LoadDefaults()
			if err != nil {
				return fail(core.ExitSoftware, err)
			}
			cmd.Printf("target: %s\n\n", args[0])
			cmd.Println("Default factor weights (ADR-006):")
			for _, name := range w.Factors() {
				cmd.Printf("  %-14s  %.2f\n", name, w.Values[name])
			}
			cmd.Println("\nSeverity derives from the score (see `elsereno scoring show`).")
			cmd.Println("Run `elsereno explain` on an NDJSON finding to see a per-factor breakdown.")
			return nil
		},
	}
}

// newTriageCmd groups a set of NDJSON findings into quick-win /
// strategic / utility / routine buckets. Input is one finding
// per line on stdin or --from-file.
func newTriageCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Group NDJSON findings into quick-win / strategic / utility / routine",
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := os.Stdin
			if path != "" {
				// #nosec G304 -- caller-supplied path
				f, err := os.Open(path)
				if err != nil {
					return fail(core.ExitIOErr, err)
				}
				defer func() { _ = f.Close() }()
				r = f
			}
			raw, err := readAll(r)
			if err != nil {
				return fail(core.ExitIOErr, err)
			}
			findings, err := parseNDJSONFindings(raw)
			if err != nil {
				return fail(core.ExitDataErr, err)
			}
			s := triageBucket(findings)
			cmd.Printf("quick_win: %d\nstrategic: %d\nutility:   %d\nroutine:   %d\n",
				len(s.QuickWin), len(s.Strategic), len(s.Utility), len(s.Routine))
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "from-file", "", "read NDJSON findings from this file (default: stdin)")
	return cmd
}

// triageBucket bridges cmd to the internal/triage package without
// importing it at the file top (keeps the command light).
type triageSummary struct {
	QuickWin  []core.Finding
	Strategic []core.Finding
	Utility   []core.Finding
	Routine   []core.Finding
}

// triageBucket mirrors internal/triage.Group: quick_win →
// strategic → utility → routine. The "utility" bucket (v1.13
// chunk 6) catches low-severity inventory / banner findings so
// the operator can separate "useful intel" from "background
// noise". See internal/triage/group.go for the canonical
// heuristic.
func triageBucket(findings []core.Finding) triageSummary {
	s := triageSummary{}
	for _, f := range findings {
		authState := 100
		impact := 0
		hasImpact := false
		if f.Factors != nil {
			if v, ok := f.Factors["auth_state"]; ok {
				authState = v
			}
			if v, ok := f.Factors["impact_class"]; ok {
				impact = v
				hasImpact = true
			}
		}
		switch {
		case (f.Severity == core.SeverityCritical || f.Severity == core.SeverityHigh) && authState <= 10:
			s.QuickWin = append(s.QuickWin, f)
		case f.Severity == core.SeverityCritical && impact >= 60:
			s.Strategic = append(s.Strategic, f)
		case isUtilityFindingLocal(f, hasImpact, impact):
			s.Utility = append(s.Utility, f)
		default:
			s.Routine = append(s.Routine, f)
		}
	}
	return s
}

// isUtilityFindingLocal mirrors the canonical heuristic in
// internal/triage. Kept as a duplicate so this file doesn't
// import the package (the bridge type triageSummary already
// implies the parallel structure).
func isUtilityFindingLocal(f core.Finding, hasImpact bool, impact int) bool {
	if f.Severity != core.SeverityInfo && f.Severity != core.SeverityLow {
		return false
	}
	if f.Protocol == "banner" || f.Protocol == "atmodem" {
		return true
	}
	if !hasImpact || impact < 20 {
		return true
	}
	return false
}

// parseNDJSONFindings decodes a buffer of newline-delimited NDJSON
// records into core.Finding values. Missing fields are tolerated.
func parseNDJSONFindings(raw []byte) ([]core.Finding, error) {
	var out []core.Finding
	for _, line := range splitLines(raw) {
		if len(line) == 0 {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(line, &doc); err != nil {
			return nil, err
		}
		var f core.Finding
		if v, ok := doc["protocol"].(string); ok {
			f.Protocol = v
		}
		if v, ok := doc["severity"].(string); ok {
			f.Severity = core.Severity(v)
		}
		if v, ok := doc["score"].(float64); ok {
			f.Score = int(v)
		}
		if v, ok := doc["factors"].(map[string]any); ok {
			f.Factors = make(map[string]int, len(v))
			for k, val := range v {
				if n, ok := val.(float64); ok {
					f.Factors[k] = int(n)
				}
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func readAll(r interface {
	Read(p []byte) (int, error)
}) ([]byte, error) {
	var buf [65536]byte
	var all []byte
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			all = append(all, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return all, nil
			}
			return all, err
		}
	}
}
