//go:build mini

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

// registerWebVerbs in the mini build registers stub verbs for
// `serve` + `api` that print a descriptive error and exit with
// EX_UNAVAILABLE (75). The stubs exist so an operator who runs
// `elsereno serve` against the mini build sees:
//
//	Error: serve is not available in this build (the mini variant
//	excludes the dashboard + HTTP API). Use the default
//	`elsereno` binary or `elsereno-offensive` from the same
//	release.
//
// instead of cobra's "unknown command" error, which is less
// helpful when the operator picked the wrong tarball.
func registerWebVerbs(root *cobra.Command) {
	root.AddCommand(miniDisabledVerb(
		"serve",
		"HTTP dashboard + /api/v1 (NOT in mini build)",
		"serve is not available in this build (the mini variant excludes the dashboard + HTTP API). Use the default `elsereno` binary or `elsereno-offensive` from the same release.",
	))
	root.AddCommand(miniDisabledVerb(
		"api",
		"OpenAPI 3.1 emitter (NOT in mini build)",
		"api is not available in this build (the mini variant excludes the OpenAPI machinery). Use the default `elsereno` binary or `elsereno-offensive` from the same release.",
	))
}

// miniDisabledVerb builds a stub cobra.Command that fails fast
// with a clear "this verb is not in the mini build" message.
// Shared shape so the error wording stays uniform across all
// excluded-in-mini verbs.
func miniDisabledVerb(use, short, longErrMsg string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fail(core.ExitUnavail, fmt.Errorf("%s", longErrMsg))
		},
	}
}
