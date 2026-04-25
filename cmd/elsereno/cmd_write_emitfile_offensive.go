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
// Optional fields:
//
//   - v1.9+:  to_prefixes (INVITE destination allowlist).
//   - v1.10+: aors (REGISTER AoR allowlist).
//   - v1.12+: from_domains (From-header domain allowlist,
//     applies to every gated method).
//
// Empty input lists are omitted from the emitted YAML so v1.4-
// era operators keep the compact method-only shape.
func buildAllowFileSIP(target string, methods, toPrefixes, aors, fromDomains []string) proxyAllowFile {
	af := proxyAllowFile{
		Plugin:  pluginNameSIP,
		Target:  target,
		Methods: canonicaliseMethodList(methods),
	}
	if sorted := trimmedDedupSorted(toPrefixes); len(sorted) > 0 {
		af.ToPrefixes = sorted
	}
	if sorted := trimmedDedupSorted(aors); len(sorted) > 0 {
		af.AORs = sorted
	}
	if sorted := trimmedDedupLowerSorted(fromDomains); len(sorted) > 0 {
		af.FromDomains = sorted
	}
	return af
}

// trimmedDedupSorted returns in trimmed of whitespace, deduped,
// case-preserved, sorted. Empty strings are dropped.
func trimmedDedupSorted(in []string) []string {
	trimmed := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		trimmed = append(trimmed, s)
	}
	stringsSort(trimmed)
	return trimmed
}

// trimmedDedupLowerSorted lowercases + trims + dedups + sorts.
// Used for the From-domain allowlist (host names are case-
// insensitive per RFC 3261 §19.1.1).
func trimmedDedupLowerSorted(in []string) []string {
	trimmed := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		trimmed = append(trimmed, s)
	}
	stringsSort(trimmed)
	return trimmed
}

// buildAllowFileIAX2 returns the YAML struct for an IAX2 dry-run.
func buildAllowFileIAX2(target string, subclasses []string) proxyAllowFile {
	return proxyAllowFile{
		Plugin:     pluginNameIAX2,
		Target:     target,
		Subclasses: canonicaliseMethodList(subclasses),
	}
}

// buildAllowFileCWMP returns the YAML struct for a CWMP dry-run.
// Optional fields:
//
//   - v1.11+: rpcs (RPC name allowlist).
//   - v1.12+: param_prefixes (Set* parameter-path allowlist).
//   - v1.12+: firmware ({url, sha256} entries for Download).
//
// RPCs are deduped, prefix-stripped, case-preserved. Parameter
// prefixes are trimmed + deduped + sorted (case preserved per
// TR-069). Firmware entries are sorted by URL.
func buildAllowFileCWMP(target string, rpcs, paramPrefixes, firmwareRaw []string) proxyAllowFile {
	af := proxyAllowFile{
		Plugin: pluginNameCWMP,
		Target: target,
	}
	if cleaned := cleanCWMPRPCs(rpcs); len(cleaned) > 0 {
		af.RPCs = cleaned
	}
	if cleaned := trimmedDedupSorted(paramPrefixes); len(cleaned) > 0 {
		af.ParamPrefixes = cleaned
	}
	if cleaned := cleanCWMPFirmware(firmwareRaw); len(cleaned) > 0 {
		af.Firmware = cleaned
	}
	return af
}

// cleanCWMPRPCs strips the optional `cwmp:` / `cwmp-1-0:`
// prefix, dedupes (case preserved per TR-069), and sorts.
func cleanCWMPRPCs(rpcs []string) []string {
	seen := map[string]struct{}{}
	trimmed := make([]string, 0, len(rpcs))
	for _, r := range rpcs {
		r = strings.TrimSpace(r)
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
	stringsSort(trimmed)
	return trimmed
}

// cleanCWMPFirmware parses raw --firmware strings, dedupes by
// (url, sha256), and sorts deterministically.
func cleanCWMPFirmware(firmwareRaw []string) []proxyCWMPFirmware {
	out := make([]proxyCWMPFirmware, 0, len(firmwareRaw))
	seen := map[string]struct{}{}
	for _, raw := range firmwareRaw {
		f, err := parseCWMPFirmwareFlag(raw)
		if err != nil {
			continue
		}
		key := f.URL + "|" + f.SHA256
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, proxyCWMPFirmware{URL: f.URL, SHA256: f.SHA256})
	}
	// Sort by (URL, SHA256) — deterministic, stable.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.URL < b.URL || (a.URL == b.URL && a.SHA256 <= b.SHA256) {
				break
			}
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
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
