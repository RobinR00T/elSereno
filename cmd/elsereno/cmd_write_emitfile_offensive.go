//go:build offensive

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"gopkg.in/yaml.v3"
)

// emitAllowFile writes the allowlist described by af to the
// operator-supplied path. Path "-" writes YAML to stdout (so
// the operator can `> file.yaml` or pipe into git). Any other
// path is created/truncated with 0600 permissions so accidental
// world-readability doesn't leak the operator's gate policy.
//
// The YAML shape matches the `proxyAllowFile` struct read by
// loadAllowFile(), guaranteeing round-trip: the file emitted
// here plugs directly into `proxy listen --allow-file` without
// further editing.
func emitAllowFile(cmd *cobra.Command, path string, af proxyAllowFile) error {
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(af); err != nil {
		return fmt.Errorf("emit allow-file: encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("emit allow-file: close: %w", err)
	}
	out := buf.String()
	if path == "-" {
		cmd.Printf("\n# --- allow-file (YAML; pipe into --allow-file) ---\n%s", out)
		return nil
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		return fmt.Errorf("emit allow-file: write %s: %w", path, err)
	}
	cmd.Printf("\nallow-file written to: %s (0600)\n", path)
	cmd.Printf("next: elsereno proxy listen --allow-file %s --accept-writes ...\n", path)
	return nil
}

// addEmitAllowFileFlag wires the --emit-allow-file flag onto a
// dry-run subcommand. Callers pass a pointer to a string that
// the cobra runtime populates; empty string means "not
// requested".
func addEmitAllowFileFlag(cmd *cobra.Command, dest *string) {
	cmd.Flags().StringVar(dest, "emit-allow-file", "",
		`write the canonical YAML allow-file to PATH ("-" for stdout) so it can be piped into proxy listen --allow-file`)
}

// buildAllowFileSIP returns the YAML struct for a SIP dry-run.
// v1.9+: optionally persists the INVITE destination prefix
// allowlist as `to_prefixes:`.
// v1.10+: optionally persists the REGISTER AOR allowlist as
// `aors:`.
func buildAllowFileSIP(target string, methods, toPrefixes, aors []string) proxyAllowFile {
	af := proxyAllowFile{
		Plugin:  pluginNameSIP,
		Target:  target,
		Methods: canonicaliseMethodList(methods),
	}
	if len(toPrefixes) > 0 {
		trimmed := make([]string, 0, len(toPrefixes))
		for _, p := range toPrefixes {
			p = strings.TrimSpace(p)
			if p != "" {
				trimmed = append(trimmed, p)
			}
		}
		if len(trimmed) > 0 {
			stringsSort(trimmed)
			af.ToPrefixes = trimmed
		}
	}
	if len(aors) > 0 {
		trimmed := make([]string, 0, len(aors))
		seen := map[string]struct{}{}
		for _, a := range aors {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			trimmed = append(trimmed, a)
		}
		if len(trimmed) > 0 {
			stringsSort(trimmed)
			af.AORs = trimmed
		}
	}
	return af
}

// buildAllowFileIAX2 returns the YAML struct for an IAX2 dry-run.
func buildAllowFileIAX2(target string, subclasses []string) proxyAllowFile {
	return proxyAllowFile{
		Plugin:     pluginNameIAX2,
		Target:     target,
		Subclasses: canonicaliseMethodList(subclasses),
	}
}

// buildAllowFileCWMP returns the YAML struct for a CWMP dry-run
// (v1.11+ rpcs:, v1.12+ param_prefixes:). RPCs are deduped,
// prefix-stripped, case-preserved (TR-069 RPC names are case-
// sensitive), and sorted for deterministic emission. Parameter
// prefixes are trimmed + deduped + sorted (case preserved, per
// TR-069 data-model conventions). Empty lists → omit the
// respective key (backwards-compat friendly).
func buildAllowFileCWMP(target string, rpcs, paramPrefixes []string) proxyAllowFile {
	af := proxyAllowFile{
		Plugin: pluginNameCWMP,
		Target: target,
	}
	if len(rpcs) > 0 {
		seen := map[string]struct{}{}
		trimmed := make([]string, 0, len(rpcs))
		for _, r := range rpcs {
			r = strings.TrimSpace(r)
			// Strip "prefix:" if present (e.g. "cwmp:Reboot").
			if i := strings.IndexByte(r, ':'); i > 0 {
				r = r[i+1:]
			}
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}
			trimmed = append(trimmed, r)
		}
		if len(trimmed) > 0 {
			stringsSort(trimmed)
			af.RPCs = trimmed
		}
	}
	if len(paramPrefixes) > 0 {
		seen := map[string]struct{}{}
		trimmed := make([]string, 0, len(paramPrefixes))
		for _, p := range paramPrefixes {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			trimmed = append(trimmed, p)
		}
		if len(trimmed) > 0 {
			stringsSort(trimmed)
			af.ParamPrefixes = trimmed
		}
	}
	return af
}

// buildAllowFilePBXHTTP returns the YAML struct for a pbxhttp
// dry-run. The `Allow` list items keep their METHOD:/path form
// so loadAllowFile + parseAllowEntry round-trip cleanly.
func buildAllowFilePBXHTTP(target string, entries []string) proxyAllowFile {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = strings.TrimSpace(e)
	}
	return proxyAllowFile{
		Plugin: pluginNamePBXHTTP,
		Target: target,
		Allow:  out,
	}
}

// canonicaliseMethodList upper-cases, trims, dedupes and sorts.
// Shared between sip + iax2 since both encode methods/
// subclasses as simple upper-case ASCII tokens.
func canonicaliseMethodList(in []string) []string {
	set := map[string]struct{}{}
	for _, m := range in {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m != "" {
			set[m] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	// sort.Strings is stable enough; we import sort elsewhere.
	stringsSort(out)
	return out
}

// stringsSort is a local wrapper so this file doesn't need
// `sort` imported just for one call. Imports like sort are
// already in play elsewhere in the package.
func stringsSort(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// ensureAllowFilePath trims whitespace and returns ErrNotSet
// when the operator didn't supply --emit-allow-file. Callers
// use this to short-circuit cleanly when the flag is absent.
var errEmitAllowFileNotSet = errors.New("emit-allow-file not set")

func ensureAllowFilePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errEmitAllowFileNotSet
	}
	return p, nil
}
