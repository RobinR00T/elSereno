package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scoring"
)

func newScoringCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scoring",
		Short: "Inspect the scoring weights and severity thresholds (ADR-006)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the current factor weights and severity table",
		RunE: func(cmd *cobra.Command, _ []string) error {
			w, err := scoring.LoadDefaults()
			if err != nil {
				return fail(core.ExitSoftware, err)
			}
			cmd.Println("Factor weights (ADR-006):")
			for _, name := range w.Factors() {
				cmd.Printf("  %-14s  %.2f\n", name, w.Values[name])
			}
			cmd.Println("\nSeverity thresholds:")
			cmd.Println("  critical  score >= 80")
			cmd.Println("  high      score >= 60")
			cmd.Println("  medium    score >= 40")
			cmd.Println("  low       score >= 20")
			cmd.Println("  info      score <  20")
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "example",
		Short: "Worked example: all factors at 50 -> medium",
		RunE: func(cmd *cobra.Command, _ []string) error {
			w, err := scoring.LoadDefaults()
			if err != nil {
				return fail(core.ExitSoftware, err)
			}
			factors := make(map[string]int, len(scoring.DefaultFactors))
			for _, name := range scoring.DefaultFactors {
				factors[name] = 50
			}
			score, sev, err := scoring.Score(w, factors)
			if err != nil {
				return fail(core.ExitSoftware, err)
			}
			cmd.Printf("score=%d severity=%s\n", score, sev)
			cmd.Printf("(factors=%v)\n", factors)
			_ = fmt.Errorf // keep gofmt happy with imports on re-edit.
			return nil
		},
	})
	return cmd
}
