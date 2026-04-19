//go:build offensive

package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scope"
	"local/elsereno/offensive/dial"
)

func newDialCmd() *cobra.Command {
	var number string
	var scopePath string
	cmd := &cobra.Command{
		Use:   "dial",
		Short: "Validate a dial number against the ADR-041 three-gate guard",
		Long: `Runs the dial guard (ADR-041):

  1. Normalise the number (strip +, 00, non-digit punctuation).
  2. Reject if ≤3 digits (unbypassable — emergency / short codes).
  3. Reject if scope.yaml's blocked_numbers matches (prefix or exact).
  4. (not in this verb) triple-confirm via offensive.confirm.Authorize.

Use this for dry-run validation before invoking a delivery channel.
Actual dial + audit wiring lands with the DB-backed audit writer.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if number == "" {
				return fail(core.ExitUsage, fmt.Errorf("--number is required"))
			}
			var sc *scope.Scope
			if scopePath != "" {
				var err error
				sc, err = scope.Load(scopePath)
				if err != nil {
					return fail(core.ExitConfig, err)
				}
			}
			norm, err := dial.Validate(number, sc)
			switch {
			case errors.Is(err, dial.ErrShortNumber):
				cmd.Printf("DENY — ≤3-digit hard block (normalised=%q)\n", norm)
				return fail(core.ExitError, err)
			case errors.Is(err, dial.ErrBlockedByScope):
				cmd.Printf("DENY — scope.yaml blocked_numbers (normalised=%q)\n", norm)
				return fail(core.ExitError, err)
			case errors.Is(err, dial.ErrEmpty):
				cmd.Println("DENY — empty / non-digit number")
				return fail(core.ExitUsage, err)
			case err != nil:
				return fail(core.ExitError, err)
			}
			cmd.Printf("ALLOW (pending triple-confirm) — normalised=%q\n", norm)
			cmd.Println()
			cmd.Println("Next: run `elsereno exploit dry-run` or `elsereno write ...` style triple-confirm flow (delivery in F6+).")
			return nil
		},
	}
	cmd.Flags().StringVar(&number, "number", "", "E.164 number to validate")
	cmd.Flags().StringVar(&scopePath, "scope", "", "optional scope.yaml path")
	return cmd
}
