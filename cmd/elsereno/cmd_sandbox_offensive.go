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
	"sort"
	"strings"

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
	cmd.AddCommand(newSandboxDiffCmd())
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

// newSandboxDiffCmd (v2.63+) — symmetric difference between
// two profile schemes. Useful for security audits: "what
// does ProfileExploit allow that ProfileScan does NOT?"
//
// Comparison is line-level after trimming whitespace, so
// the indented continuation lines of multi-line clauses
// (e.g. `(allow file-write* (subpath "/tmp"))`) are
// compared as their own lines. Operators get a fast,
// deterministic answer without paying for a structured
// Scheme-clause parser.
func newSandboxDiffCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "diff PROFILE_A PROFILE_B",
		Short: "Compare two sandbox profile schemes (darwin+cgo only)",
		Long: `Shows which lines appear in one profile's .sb Scheme but
not the other. Comparison is line-level after whitespace
trimming, so a multi-line clause like

  (allow file-write*
      (subpath "/tmp"))

is treated as two lines and lines that match across
profiles are filtered out as "common".

Text mode prints a unified-style report with a header
naming both profiles and ` + "`+`" + ` / ` + "`-`" + ` line prefixes. JSON
mode emits a stable shape:
  {"a": "exploit", "b": "scan",
   "only_in_a": [...], "only_in_b": [...], "common": [...]}.

Requires the darwin+cgo build. On every other offensive
build the verb exits with a clear "schemes unavailable"
error so operators don't silently get an all-empty diff.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, posArgs []string) error {
			return runSandboxDiff(cmd, posArgs[0], posArgs[1], jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the diff as a JSON object (a/b/only_in_a/only_in_b/common)")
	return cmd
}

// sandboxDiffResult is the JSON-emitted shape for
// `sandbox diff`. Field names match the documented contract.
type sandboxDiffResult struct {
	A       string   `json:"a"`
	B       string   `json:"b"`
	OnlyInA []string `json:"only_in_a"`
	OnlyInB []string `json:"only_in_b"`
	Common  []string `json:"common"`
}

// runSandboxDiff fetches both schemes via schemeForProfile,
// validates the requested profiles, then computes the
// symmetric difference + intersection. Output rendered in
// either text-unified or JSON format.
func runSandboxDiff(cmd *cobra.Command, nameA, nameB string, jsonOut bool) error {
	pA := sandbox.Profile(nameA)
	if !pA.Valid() {
		return fail(core.ExitUsage, fmt.Errorf("sandbox: unknown profile %q (try `elsereno sandbox list`)", nameA))
	}
	pB := sandbox.Profile(nameB)
	if !pB.Valid() {
		return fail(core.ExitUsage, fmt.Errorf("sandbox: unknown profile %q (try `elsereno sandbox list`)", nameB))
	}

	scmA, okA, err := schemeForProfile(pA)
	if err != nil {
		return err
	}
	scmB, okB, err := schemeForProfile(pB)
	if err != nil {
		return err
	}
	if !okA || !okB || (scmA == "" && scmB == "") {
		return fail(core.ExitError, fmt.Errorf("sandbox diff: schemes unavailable on this build (need darwin+cgo); see `elsereno sandbox introspect --help`"))
	}

	result := diffSchemes(string(pA), string(pB), scmA, scmB)

	if jsonOut {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}
	cmd.Printf("# diff sandbox profiles: A=%s  B=%s\n", result.A, result.B)
	cmd.Printf("# common=%d  only_in_a=%d  only_in_b=%d\n",
		len(result.Common), len(result.OnlyInA), len(result.OnlyInB))
	if len(result.OnlyInA) == 0 && len(result.OnlyInB) == 0 {
		cmd.Println("# (profiles are equivalent at line level)")
		return nil
	}
	for _, line := range result.OnlyInA {
		cmd.Printf("- %s\n", line)
	}
	for _, line := range result.OnlyInB {
		cmd.Printf("+ %s\n", line)
	}
	return nil
}

// diffSchemes computes the line-level set difference +
// intersection between two .sb Scheme strings. Output
// arrays are sorted lexicographically so the result is
// deterministic across runs (operators piping to `diff` /
// `git diff` of two captures need stable ordering). The
// "common" array is included so operators can sanity-check
// that the comparison is comparing what they think.
//
// Empty / whitespace-only lines are dropped — they're not
// semantically meaningful in .sb Scheme.
func diffSchemes(nameA, nameB, scmA, scmB string) sandboxDiffResult {
	setA := schemeLineSet(scmA)
	setB := schemeLineSet(scmB)

	onlyA, onlyB, common := []string{}, []string{}, []string{}
	for line := range setA {
		if _, in := setB[line]; in {
			common = append(common, line)
		} else {
			onlyA = append(onlyA, line)
		}
	}
	for line := range setB {
		if _, in := setA[line]; !in {
			onlyB = append(onlyB, line)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	sort.Strings(common)
	return sandboxDiffResult{
		A:       nameA,
		B:       nameB,
		OnlyInA: onlyA,
		OnlyInB: onlyB,
		Common:  common,
	}
}

// schemeLineSet returns the set of non-whitespace-only lines
// in scm, with leading/trailing whitespace trimmed from each
// line. The set keys are the trimmed lines themselves.
func schemeLineSet(scm string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, line := range strings.Split(scm, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		out[t] = struct{}{}
	}
	return out
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
