package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scope"
)

// scopeGate is the --scope check a network command runs before it
// opens a connection. Until 2026-10-17 only scan, serve and dial took
// --scope, so a scope.yaml limited nothing else (PITF-095). A zero
// gate (no --scope) lets everything through, as before.
type scopeGate struct {
	sc *scope.Scope
}

// addScopeFlag registers --scope on a network command.
func addScopeFlag(cmd *cobra.Command, path *string) {
	cmd.Flags().StringVar(path, "scope", "",
		"scope.yaml: refuse targets outside its ranges and ports, and, where the command runs a plugin, plugins outside its protocols (elsereno-scope(5))")
}

// loadScopeGate reads --scope. A file that does not parse is a
// configuration error (78), so a typo never means "no scope".
func loadScopeGate(path string) (scopeGate, error) {
	sc, err := scope.Load(path)
	if err != nil {
		return scopeGate{}, fail(core.ExitConfig, err)
	}
	return scopeGate{sc: sc}, nil
}

// active reports whether a scope was given.
func (g scopeGate) active() bool { return g.sc != nil }

// plugin refuses a plugin the scope's protocols lists leave out (77).
func (g scopeGate) plugin(name string) error {
	if err := g.sc.CheckPlugin(name); err != nil {
		return fail(core.ExitNoPerm, err)
	}
	return nil
}

// target refuses an address and port outside the scope's ranges and
// ports, or (when plugin is not empty) a plugin outside its protocols,
// with exit 77.
func (g scopeGate) target(t core.Target, plugin string) error {
	if err := g.sc.Check(t); err != nil {
		return fail(core.ExitNoPerm, fmt.Errorf("%s: %w", netip.AddrPortFrom(t.Address, uint16(t.Port)), err))
	}
	if plugin != "" {
		return g.plugin(plugin)
	}
	return nil
}

// hostPort checks a host:port the command is about to connect to and
// returns the address to connect to. Without a scope it returns the
// input untouched. With one, a name is resolved once, its first
// address is checked, and that address is returned, so the name cannot
// resolve to one address for the check and to another for the
// connection.
func (g scopeGate) hostPort(ctx context.Context, hostport, plugin string) (string, error) {
	if !g.active() {
		return hostport, nil
	}
	t, err := resolveHostPort(ctx, hostport)
	if err != nil {
		return "", err
	}
	if err := g.target(t, plugin); err != nil {
		return "", err
	}
	return netip.AddrPortFrom(t.Address, uint16(t.Port)).String(), nil
}

// resolveHostPort turns host:port into a target: an IP literal as is, a
// name resolved to its first address. A bad form is a usage error (64);
// a name that does not resolve, 68.
func resolveHostPort(ctx context.Context, hostport string) (core.Target, error) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return core.Target{Address: ap.Addr().Unmap(), Port: core.Port(ap.Port())}, nil
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return core.Target{}, fail(core.ExitUsage, fmt.Errorf("%q: want host:port", hostport))
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 0 || p > 65535 {
		return core.Target{}, fail(core.ExitUsage, fmt.Errorf("%q: bad port %q", hostport, portStr))
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return core.Target{}, fail(core.ExitNoHost, fmt.Errorf("%q: resolve %q: %w", hostport, host, err))
	}
	// #nosec G115 -- p is bounds-checked to [0,65535] above.
	return core.Target{Address: addrs[0].Unmap(), Port: core.Port(p)}, nil
}

// scopedHostPort is loadScopeGate plus hostPort, for the commands that
// take a single --target.
func scopedHostPort(cmd *cobra.Command, scopePath, target, plugin string) (string, error) {
	gate, err := loadScopeGate(scopePath)
	if err != nil {
		return "", err
	}
	return gate.hostPort(cmd.Context(), target, plugin)
}

// literalTarget checks the target of a write, exploit or proxy verb
// (harvest resolves names through hostPort). With a scope it must be an IP:port literal: a write's confirm
// token is computed over the target as typed, so it cannot be swapped
// for a resolved address, and a name could resolve elsewhere between
// the check and the connection. Without a scope it checks nothing.
func (g scopeGate) literalTarget(target, plugin string) error {
	if !g.active() {
		return nil
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		return fail(core.ExitUsage, fmt.Errorf("--target %q: with --scope give an IP:port, not a name", target))
	}
	return g.target(core.Target{Address: ap.Addr().Unmap(), Port: core.Port(ap.Port())}, plugin)
}

// urlDialAddr checks the host and port of an http(s) URL and returns
// the address every request must connect to: "" without a scope. With
// one, the host is resolved once and checked (the port is the URL's,
// or 80 or 443 by scheme), and the caller pins its dialer to the
// returned address, so the Host header and SNI keep the name while the
// connection goes to the checked IP.
func (g scopeGate) urlDialAddr(ctx context.Context, rawURL, plugin string) (string, error) {
	if !g.active() {
		return "", nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", fail(core.ExitUsage, fmt.Errorf("--target %q: want an http(s) URL", rawURL))
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fail(core.ExitUsage, fmt.Errorf("--target %q: scheme %q has no default port; give one", rawURL, u.Scheme))
		}
	}
	return g.hostPort(ctx, net.JoinHostPort(u.Hostname(), port), plugin)
}

// scopePlugins applies the protocols lists to the plugins a scan is
// about to run (PITF-095). A plugin the operator named that the scope
// refuses is an error (77): the scan would not be the one asked for.
// With no names (every plugin), the refused ones are left out and
// returned, so the caller can say which.
func scopePlugins(sc *scope.Scope, named bool, plugins []core.Plugin) ([]core.Plugin, []string, error) {
	if sc == nil {
		return plugins, nil, nil
	}
	kept := make([]core.Plugin, 0, len(plugins))
	var refused []string
	for _, p := range plugins {
		if err := sc.CheckPlugin(p.Name); err != nil {
			if named {
				return nil, nil, fail(core.ExitNoPerm, err)
			}
			refused = append(refused, p.Name)
			continue
		}
		kept = append(kept, p)
	}
	return kept, refused, nil
}

// scopedLiteral is loadScopeGate plus literalTarget, for the
// write-class verbs.
func scopedLiteral(scopePath, target, plugin string) error {
	gate, err := loadScopeGate(scopePath)
	if err != nil {
		return err
	}
	return gate.literalTarget(target, plugin)
}

// targetVerb holds the flags of a read-only verb that probes a single
// --target (plaintext-check and the s7 probes) and applies --scope to
// it before connecting.
type targetVerb struct {
	target, scopePath string
	timeout           time.Duration
	jsonOut           bool
}

// register adds --target, --timeout, --json and --scope.
func (v *targetVerb) register(cmd *cobra.Command, targetHelp string, timeout time.Duration, timeoutHelp string) {
	cmd.Flags().StringVar(&v.target, "target", "", targetHelp)
	cmd.Flags().DurationVar(&v.timeout, "timeout", timeout, timeoutHelp)
	cmd.Flags().BoolVar(&v.jsonOut, "json", false, "emit the result as JSON")
	addScopeFlag(cmd, &v.scopePath)
}

// runE requires --target, checks it (and plugin, when not empty)
// against --scope, and calls run with the address to connect to.
func (v *targetVerb) runE(plugin string, run func(cmd *cobra.Command, target string, timeout time.Duration, jsonOut bool) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		if v.target == "" {
			return errors.New("--target host:port is required")
		}
		dialTarget, err := scopedHostPort(cmd, v.scopePath, v.target, plugin)
		if err != nil {
			return err
		}
		return run(cmd, dialTarget, v.timeout, v.jsonOut)
	}
}
