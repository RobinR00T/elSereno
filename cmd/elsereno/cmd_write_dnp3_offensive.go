//go:build offensive

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	dnpwrite "local/elsereno/offensive/write/dnp3"
)

// dnp3ProxyFlags groups the CLI flags for the DNP3 proxy-session
// dry-run. The same four allowlist flags are accepted verbatim by
// `proxy listen --plugin dnp3`, so a minted token matches the session.
type dnp3ProxyFlags struct {
	target, ppFile string
	appFCs         []string // --dnp3-app-fc (hex/dec)
	links          []string // --dnp3-link src=N;dest=M
	controls       []string // --dnp3-control index=A-B;code=0x03,0x04
	primaries      []string // --dnp3-primary (link-layer FC)
}

func newWriteDNP3Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnp3",
		Short: "DNP3 write-gated proxy (proxy-dry-run derives the session confirm-token)",
	}
	cmd.AddCommand(newWriteDNP3ProxyDryRunCmd())
	return cmd
}

func newWriteDNP3ProxyDryRunCmd() *cobra.Command {
	var f dnp3ProxyFlags
	cmd := &cobra.Command{
		Use:   "proxy-dry-run",
		Short: "Proxy-session dry-run: derive the confirm-token for `proxy listen --plugin dnp3`",
		Long: `Takes a DNP3 allowlist and prints the canonical SessionMutation +
PayloadHash, and (with --vault-passphrase-file) the expected
confirm-token.

Reads (Class 0/1/2/3 polls, FC 1) always pass. Everything else is
default-deny: an application function code must be listed with
--dnp3-app-fc to pass, a control to a broadcast address (0xFFFD-0xFFFF)
is always refused, and --dnp3-control scopes an Operate / Direct
Operate to a (point-index, control-code) allowlist.

Application function codes (--dnp3-app-fc): 0x02 Write, 0x03 Select,
0x04 Operate, 0x05 Direct Operate, 0x06 Direct Operate No-Ack,
0x0D Cold Restart, 0x0E Warm Restart, 0x12 Stop Application,
0x15 Disable Unsolicited.

CROB control codes (--dnp3-control code=): 0x03 LATCH_ON, 0x04
LATCH_OFF, 0x41 CLOSE+PULSE_ON, 0x81 TRIP+PULSE_ON. Example: allow a
latch on points 5-8 but never a trip or close:
  --dnp3-app-fc 0x05 --dnp3-control "index=5-8;code=0x03,0x04"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWriteDNP3ProxyDryRun(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.target, "target", "", "upstream host:port (the DNP3 outstation we'll proxy to)")
	addDNP3AllowlistFlags(cmd.Flags(), &f.appFCs, &f.links, &f.controls, &f.primaries)
	addPassphraseFileFlag(cmd, &f.ppFile)
	return cmd
}

// dnp3FlagSet is the cobra FlagSet subset the shared registrar needs.
// StringArrayVar (not StringSliceVar) is deliberate: --dnp3-control
// carries a comma-separated code= list, which the comma-splitting
// slice flag would mangle.
type dnp3FlagSet interface {
	StringArrayVar(p *[]string, name string, value []string, usage string)
}

// addDNP3AllowlistFlags registers the four allowlist flags shared by
// the dry-run and `proxy listen --plugin dnp3`. Each is repeatable;
// none splits on commas.
func addDNP3AllowlistFlags(fs dnp3FlagSet, appFCs, links, controls, primaries *[]string) {
	fs.StringArrayVar(appFCs, "dnp3-app-fc", nil,
		"DNP3 application function code to allow (hex 0x05 or decimal; repeatable). "+
			"Read (0x01) is always allowed. e.g. 0x05 Direct Operate, 0x02 Write.")
	fs.StringArrayVar(controls, "dnp3-control", nil,
		"scope a Control Relay Output Block: index=A-B;code=0x03,0x04 (repeatable). "+
			"index is one point or a range; code is an optional control-code allowlist "+
			"(omit = any code on that range). e.g. index=5-8;code=0x03,0x04.")
	fs.StringArrayVar(links, "dnp3-link", nil,
		"pin a master->outstation link-address pair: src=N;dest=M (repeatable). "+
			"A zero/omitted field is a wildcard. Mutating frames from an unpinned pair are refused.")
	fs.StringArrayVar(primaries, "dnp3-primary", nil,
		"link-layer primary function code to allow (optional; repeatable). "+
			"Default policy accepts user-data frames and lets the app-layer gate decide.")
}

func runWriteDNP3ProxyDryRun(cmd *cobra.Command, f dnp3ProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	if len(f.appFCs) == 0 && len(f.controls) == 0 && len(f.links) == 0 && len(f.primaries) == 0 {
		return fail(core.ExitUsage, errors.New(
			"at least one of --dnp3-app-fc / --dnp3-control / --dnp3-link / --dnp3-primary is required"))
	}
	al, err := buildDNP3Allowlist(f.appFCs, f.links, f.controls, f.primaries)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	mut := dnpwrite.SessionMutation(f.target, al)
	rows := [][2]string{}
	if len(f.appFCs) > 0 {
		rows = append(rows, [2]string{"AppFCs", strings.Join(f.appFCs, " ")})
	}
	if len(f.controls) > 0 {
		rows = append(rows, [2]string{"Controls", strings.Join(f.controls, " ")})
	}
	if len(f.links) > 0 {
		rows = append(rows, [2]string{"Links", strings.Join(f.links, " ")})
	}
	if len(f.primaries) > 0 {
		rows = append(rows, [2]string{"Primaries", strings.Join(f.primaries, " ")})
	}
	return printProxyDryRun(cmd, "dnp3", f.target, rows, mut, f.ppFile)
}

// buildDNP3Allowlist parses the four raw flag slices into the library
// allowlist. Shared by the dry-run mint and buildDNP3Handler so the
// token always matches the running session.
func buildDNP3Allowlist(appFCs, links, controls, primaries []string) (dnpwrite.Allowlist, error) {
	var al dnpwrite.Allowlist
	for _, raw := range appFCs {
		v, err := strconv.ParseUint(strings.TrimSpace(raw), 0, 8)
		if err != nil {
			return al, fmt.Errorf("--dnp3-app-fc %q: %w", raw, err)
		}
		al.AppFC = append(al.AppFC, dnpwrite.AllowedAppFunction{FC: uint8(v)}) // #nosec G115 -- bitSize 8
	}
	for _, raw := range primaries {
		v, err := strconv.ParseUint(strings.TrimSpace(raw), 0, 8)
		if err != nil {
			return al, fmt.Errorf("--dnp3-primary %q: %w", raw, err)
		}
		al.Control = append(al.Control, dnpwrite.AllowedControl{PrimaryFC: uint8(v)}) // #nosec G115 -- bitSize 8
	}
	for _, raw := range links {
		lp, err := parseDNP3Link(raw)
		if err != nil {
			return al, err
		}
		al.Links = append(al.Links, lp)
	}
	for _, raw := range controls {
		c, err := parseDNP3Control(raw)
		if err != nil {
			return al, err
		}
		al.ControlOutput = append(al.ControlOutput, c)
	}
	return al, nil
}

// parseDNP3Link parses "src=N;dest=M" into a LinkPair. Each field is a
// uint16 (hex or decimal); a missing field defaults to 0 (wildcard).
func parseDNP3Link(s string) (dnpwrite.LinkPair, error) {
	var lp dnpwrite.LinkPair
	seen := false
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return lp, fmt.Errorf("--dnp3-link %q: expected src=N;dest=M", s)
		}
		v, err := strconv.ParseUint(strings.TrimSpace(kv[1]), 0, 16)
		if err != nil {
			return lp, fmt.Errorf("--dnp3-link %q: %w", s, err)
		}
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "src":
			lp.Src = uint16(v) // #nosec G115 -- bitSize 16
		case "dest", "dst":
			lp.Dest = uint16(v) // #nosec G115 -- bitSize 16
		default:
			return lp, fmt.Errorf("--dnp3-link %q: unknown key %q", s, kv[0])
		}
		seen = true
	}
	if !seen {
		return lp, fmt.Errorf("--dnp3-link %q: empty", s)
	}
	return lp, nil
}

// parseDNP3Control parses "index=A-B;code=X,Y" into an
// AllowedCROBControl. `index` is a single point or an A-B range; `code`
// is an optional comma-separated control-code allowlist.
func parseDNP3Control(s string) (dnpwrite.AllowedCROBControl, error) {
	var c dnpwrite.AllowedCROBControl
	indexSeen := false
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return c, fmt.Errorf("--dnp3-control %q: expected index=A-B;code=X,Y", s)
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "index", "idx":
			start, end, err := parseIndexRange(val)
			if err != nil {
				return c, fmt.Errorf("--dnp3-control %q: %w", s, err)
			}
			c.IndexStart, c.IndexEnd, indexSeen = start, end, true
		case "code", "codes":
			for _, cs := range strings.Split(val, ",") {
				cs = strings.TrimSpace(cs)
				if cs == "" {
					continue
				}
				v, err := strconv.ParseUint(cs, 0, 8)
				if err != nil {
					return c, fmt.Errorf("--dnp3-control %q: code %q: %w", s, cs, err)
				}
				c.Codes = append(c.Codes, uint8(v)) // #nosec G115 -- bitSize 8
			}
		default:
			return c, fmt.Errorf("--dnp3-control %q: unknown key %q", s, kv[0])
		}
	}
	if !indexSeen {
		return c, fmt.Errorf("--dnp3-control %q: index= is required", s)
	}
	return c, nil
}

// parseIndexRange parses "A" or "A-B" into an inclusive uint16 range.
func parseIndexRange(v string) (start, end uint16, err error) {
	if dash := strings.IndexByte(v, '-'); dash >= 0 {
		lo, e1 := strconv.ParseUint(strings.TrimSpace(v[:dash]), 0, 16)
		hi, e2 := strconv.ParseUint(strings.TrimSpace(v[dash+1:]), 0, 16)
		if e1 != nil || e2 != nil {
			return 0, 0, fmt.Errorf("bad index range %q", v)
		}
		if hi < lo {
			return 0, 0, fmt.Errorf("index range %q: start > end", v)
		}
		return uint16(lo), uint16(hi), nil // #nosec G115 -- bitSize 16
	}
	n, e := strconv.ParseUint(strings.TrimSpace(v), 0, 16)
	if e != nil {
		return 0, 0, fmt.Errorf("bad index %q", v)
	}
	return uint16(n), uint16(n), nil // #nosec G115 -- bitSize 16
}
