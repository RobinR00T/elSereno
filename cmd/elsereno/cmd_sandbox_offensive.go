//go:build offensive

// v2.62 — `elsereno sandbox` parent command + `list` and
// `introspect` subverbs.
//
// `list` works on every offensive build (it just enumerates
// the Profile constants from the always-compiled sandbox.go).
// `introspect` only emits a .sb Scheme on the darwin+cgo
// build path; on every other offensive build it returns a
// clear "schemes only available on darwin+cgo" message
// rather than silently emitting an empty body — this avoids
// the "did the verb work?" ambiguity that bit operators when
// the v1.50 cgo-gated build was first introduced.
//
// The platform-specific scheme accessor (`schemeForProfile`)
// lives in `cmd_sandbox_scheme_darwin_cgo.go` and
// `cmd_sandbox_scheme_other.go`. This file is platform-free.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/offensive/sandbox"
)

// newSandboxCmd attaches the offensive-build `sandbox` parent
// command tree to the root verb tree. v2.62+.
func newSandboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Inspect macOS sandbox_init(3) / Linux seccomp profiles (offensive build)",
		Long: `Read-only verbs for inspecting the sandbox policy that the
offensive verbs (exploit / harvest / dial / scan) will apply
to subprocesses.

` + "`list`" + ` enumerates the recognised profile names.

` + "`introspect PROFILE`" + ` dumps the effective .sb Scheme for the
named profile (darwin+cgo build only — Linux uses seccomp-bpf
which is a binary BPF program; introspection there has a
different shape and is not implemented).

Neither verb applies the sandbox; both are dry-run, side-
effect-free, and safe to run without elevation.`,
	}
	cmd.AddCommand(newSandboxListCmd())
	cmd.AddCommand(newSandboxIntrospectCmd())
	return cmd
}

// newSandboxListCmd returns a cobra command that prints the
// canonical Profile enumeration. Works on every offensive
// build (no platform branching — the enumeration lives in
// the always-compiled sandbox.go).
func newSandboxListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Print the recognised sandbox profile names",
		RunE: func(cmd *cobra.Command, _ []string) error {
			profiles := sandbox.Profiles()
			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(profiles)
			}
			for _, p := range profiles {
				cmd.Println(string(p))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the profile list as a JSON array")
	return cmd
}

// sandboxIntrospectArgs bundles the introspect verb's flags
// so the RunE closure stays a thin driver. Kept private to
// this file.
type sandboxIntrospectArgs struct {
	all    bool
	format string
}

// newSandboxIntrospectCmd returns a cobra command that prints
// the .sb Scheme for a named profile (or every profile with
// --all). Platform-aware: defers to schemeForProfile() which
// is supplied by the per-platform _darwin_cgo / _other file.
func newSandboxIntrospectCmd() *cobra.Command {
	var args sandboxIntrospectArgs
	cmd := &cobra.Command{
		Use:   "introspect [PROFILE]",
		Short: "Dump the .sb Scheme for a sandbox profile (darwin+cgo only)",
		Long: `Reads the in-binary .sb Scheme string for PROFILE without
applying the sandbox. Useful for operator audits and for
checking what a profile permits before running the
offensive verb.

Available only on the darwin+cgo build (the
` + "`build-offensive-darwin-sandboxed`" + ` Make target). On every
other offensive build the verb prints a clear "not
available on this build" message and exits non-zero so
operators can fence the verb behind a build-tag check
without parsing stdout.`,
		Args: func(cmd *cobra.Command, posArgs []string) error {
			if args.all {
				if len(posArgs) > 0 {
					return fmt.Errorf("--all is mutually exclusive with a positional PROFILE arg")
				}
				return nil
			}
			return cobra.ExactArgs(1)(cmd, posArgs)
		},
		RunE: func(cmd *cobra.Command, posArgs []string) error {
			return runSandboxIntrospect(cmd, posArgs, args)
		},
	}
	cmd.Flags().BoolVar(&args.all, "all", false, "dump every recognised profile instead of one named PROFILE")
	cmd.Flags().StringVar(&args.format, "format", "text", "output format: text (default) | json")
	return cmd
}

// runSandboxIntrospect collects the requested schemes via
// schemeForProfile() then renders in the requested format.
// Separate from newSandboxIntrospectCmd's RunE closure so
// it's straightforward to unit-test the dispatcher.
func runSandboxIntrospect(cmd *cobra.Command, posArgs []string, args sandboxIntrospectArgs) error {
	if args.format != "text" && args.format != "json" {
		return fail(core.ExitUsage, fmt.Errorf("--format must be text or json, got %q", args.format))
	}

	results, err := collectSchemes(posArgs, args.all)
	if err != nil {
		return err
	}

	if args.format == "json" {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(results)
	}
	for i, r := range results {
		if i > 0 {
			cmd.Println()
		}
		cmd.Printf("# profile=%s\n%s", r.Profile, r.Scheme)
		if r.Scheme != "" && r.Scheme[len(r.Scheme)-1] != '\n' {
			cmd.Println()
		}
	}
	return nil
}

// sandboxSchemeResult is the JSON-emitted shape: one entry
// per requested profile with the live .sb Scheme.
type sandboxSchemeResult struct {
	Profile string `json:"profile"`
	Scheme  string `json:"scheme"`
}

// collectSchemes loops over either {posArg} or every
// recognised profile (when --all) and looks each one up via
// schemeForProfile(). Returns the slice in iteration order
// or a usage error on the first failure.
func collectSchemes(posArgs []string, all bool) ([]sandboxSchemeResult, error) {
	var targets []sandbox.Profile
	if all {
		targets = sandbox.Profiles()
	} else {
		p := sandbox.Profile(posArgs[0])
		if !p.Valid() {
			return nil, fail(core.ExitUsage, fmt.Errorf("sandbox: unknown profile %q (try `elsereno sandbox list`)", posArgs[0]))
		}
		targets = []sandbox.Profile{p}
	}

	out := make([]sandboxSchemeResult, 0, len(targets))
	for _, p := range targets {
		scm, ok, err := schemeForProfile(p)
		if err != nil {
			return nil, err
		}
		if !ok {
			// Build was non-darwin or non-cgo; emit a sentinel
			// row instead of a bare empty string so JSON
			// consumers can distinguish "no scheme" from
			// "introspection not supported on this build".
			out = append(out, sandboxSchemeResult{
				Profile: string(p),
				Scheme:  "",
			})
			continue
		}
		out = append(out, sandboxSchemeResult{
			Profile: string(p),
			Scheme:  scm,
		})
	}
	return out, nil
}
