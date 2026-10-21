package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/time/rate"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
)

// discoverDefaultMaxHosts caps the number of CIDR addresses
// the auto-discover walks by default. /24 = 256 hosts is a
// reasonable lab / per-VLAN sweep; operators sweeping larger
// ranges pass --max-hosts explicitly so they confirm they
// understand the parallel-connect budget.
const discoverDefaultMaxHosts = 256

// discoverDefaultDialTimeout caps each TCP-connect attempt.
// 1 s is aggressive enough for a LAN sweep and slow enough to
// not panic SYN-rate-limited middleboxes.
const discoverDefaultDialTimeout = 1 * time.Second

// discoverDefaultParallel is the per-CIDR concurrency. 64 is
// a balance between sweep speed and connection-pool pressure
// on the operator's outbound NIC.
const discoverDefaultParallel = 64

func newDiscoverCmd() *cobra.Command {
	var (
		auto         string
		hostsFile    string
		maxHosts     int
		dialTimeout  time.Duration
		parallel     int
		outputFormat string
		scopePath    string
		pf           pacingFlags
	)
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Sweep a CIDR or host list for ports of every registered plugin",
		Long: `discover --auto <CIDR> performs a TCP-connect sweep
of the well-known ports of every registered ElSereno plugin
across the supplied CIDR. Responsive (host, port) pairs are
emitted to stdout as NDJSON, or as host:port lines with
--format list, which pipes into ` + "`elsereno scan --input list:-`" + `
for protocol-aware fingerprinting on the responsive subset.

discover --hosts <file> (v1.39+) sweeps the same plugin-port
list against a fixed list of hosts (one IP per line, # for
comments). Useful when the operator already has a curated
inventory and wants to avoid expanding a sparse CIDR. Mutex
with --auto.

Goal: skip the manual port-list maintenance step. The operator
points at a CIDR or host list, gets a "what's actually
listening" inventory in one command, and the deep-scan phase
only runs against hosts that responded.

The walk is bounded by --max-hosts (default 256, i.e. /24
sized) and --parallel (default 64 concurrent connects). Use
--dial-timeout to tune for slow links.

One host gets at most scanner.max_concurrent_per_host connects at a
time (1 by default; --max-conns-per-host or the profile change it),
and the sweep walks port by port across the hosts, so 64 connects
spread over 64 hosts instead of landing on the ports of one. Before
2026-10-21 every port of a host was dialled at once.

` + profilesHelp() + `

With --scope, only the hosts in its ranges are swept, and only the
ports its ports lists allow for the plugins its protocols lists allow.
--max-hosts counts before that filter.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiscover(cmd, auto, hostsFile, maxHosts, parallel, dialTimeout, outputFormat, scopePath, pf)
		},
	}
	cmd.Flags().StringVar(&auto, "auto", "", "CIDR to sweep (e.g. 192.168.1.0/24)")
	cmd.Flags().StringVar(&hostsFile, "hosts", "",
		"v1.39+: file with one IP per line (# for comments). Mutex with --auto.")
	cmd.Flags().IntVar(&maxHosts, "max-hosts", discoverDefaultMaxHosts, "cap on hosts walked (CIDR or file)")
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", discoverDefaultDialTimeout, "per-(host, port) TCP-connect timeout")
	cmd.Flags().IntVar(&parallel, "parallel", discoverDefaultParallel, "max concurrent TCP-connects")
	cmd.Flags().StringVar(&outputFormat, "format", "ndjson", "output format: ndjson | list (host:port one per line)")
	addScopeFlag(cmd, &scopePath)
	addPacingFlags(cmd, &pf)
	return cmd
}

// runDiscover dispatches the actual discover work. Extracted
// from newDiscoverCmd's RunE so the parent stays under funlen
// as new flags land.
func runDiscover(cmd *cobra.Command, auto, hostsFile string, maxHosts, parallel int, dialTimeout time.Duration, outputFormat, scopePath string, pf pacingFlags) error {
	if (auto == "") == (hostsFile == "") {
		return fail(core.ExitUsage,
			errors.New("exactly one of --auto <CIDR> or --hosts <file> is required"))
	}
	pace, parallel, err := discoverPacing(cmd, pf, parallel)
	if err != nil {
		return err
	}
	gate, err := loadScopeGate(scopePath)
	if err != nil {
		return err
	}
	ports := registeredPluginPorts()
	if len(ports) == 0 {
		return fail(core.ExitSoftware, errors.New("no plugins registered, link with the protocol packages"))
	}
	var hosts []netip.Addr
	if auto != "" {
		hosts, err = expandCIDR(auto, maxHosts)
	} else {
		hosts, err = loadDiscoverHostsFile(hostsFile, maxHosts)
	}
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	if gate.active() {
		// Nothing outside the scope is connected to (PITF-095).
		hosts, ports = scopeDiscover(gate, hosts, ports)
		if len(hosts) == 0 || len(ports) == 0 {
			return fail(core.ExitNoInput, fmt.Errorf("no hosts or ports left after scope filter (%d hosts, %d ports)", len(hosts), len(ports)))
		}
	}
	printDiscoverPace(cmd.ErrOrStderr(), pace, parallel, len(uniquePorts(ports)))
	results := sweepPaced(cmd.Context(), hosts, ports, dialTimeout, sweepPace{
		parallel:   parallel,
		pacer:      scanner.NewHostPacer(pace.maxPerHost, pace.interval),
		ratePerSec: pace.ratePerSec,
	})
	return emitDiscoverResults(cmd.OutOrStdout(), cmd.ErrOrStderr(), results, outputFormat)
}

// discoverPacing resolves discover's pace. discover has no retries
// and its global cap is --parallel, not the config's
// max_concurrent_targets: the profile's in-flight cap applies only when
// it is lower than --parallel and --parallel was not given.
func discoverPacing(cmd *cobra.Command, pf pacingFlags, parallel int) (pacing, int, error) {
	cfg, _, err := loadConfig()
	if err != nil {
		return pacing{}, 0, fail(core.ExitConfig, err)
	}
	pace, err := resolvePacing(cmd, pf, cfg.Scanner, pacingOverrides{})
	if err != nil {
		return pacing{}, 0, err
	}
	if !cmd.Flags().Changed("parallel") && pace.maxConcurrent > 0 && pace.maxConcurrent < parallel && pace.profile != scanner.DefaultProfile {
		parallel = pace.maxConcurrent
	}
	if parallel < 1 {
		return pacing{}, 0, fail(core.ExitUsage, errors.New("--parallel must be at least 1"))
	}
	return pace, parallel, nil
}

// printDiscoverPace tells the operator the pace the sweep runs with.
// With a pause, one host's ports alone set a floor on the run time;
// it says so, so a fragile sweep is not taken for a hang.
func printDiscoverPace(w io.Writer, pace pacing, parallel, portsPerHost int) {
	_, _ = fmt.Fprintf(w, "elsereno discover: %d parallel, %d per host, %s\n",
		parallel, pace.maxPerHost, describeGapRate(pace))
	if pace.interval > 0 && portsPerHost > 1 {
		minimum := time.Duration(portsPerHost-1) * pace.interval
		_, _ = fmt.Fprintf(w, "elsereno discover: %d ports per host, so at least %s\n", portsPerHost, minimum)
	}
}

// scopeDiscover keeps the hosts in the scope's ranges and the
// (port, plugin) entries whose port the ports lists allow and whose
// plugin the protocols lists allow. A port shared by an allowed and a
// denied plugin is swept for the allowed one.
func scopeDiscover(gate scopeGate, hosts []netip.Addr, ports []pluginPort) ([]netip.Addr, []pluginPort) {
	keptHosts := make([]netip.Addr, 0, len(hosts))
	for _, h := range hosts {
		if gate.sc.CheckAddr(h) == nil {
			keptHosts = append(keptHosts, h)
		}
	}
	keptPorts := make([]pluginPort, 0, len(ports))
	for _, p := range ports {
		if gate.sc.CheckPort(p.Port) == nil && gate.sc.CheckPlugin(p.PluginID) == nil {
			keptPorts = append(keptPorts, p)
		}
	}
	return keptHosts, keptPorts
}

// loadDiscoverHostsFile parses a host-list file: one IP per
// line, # for comments, blanks ignored. Returns at most
// maxHosts entries (0 = unbounded). v1.39+.
func loadDiscoverHostsFile(path string, maxHosts int) ([]netip.Addr, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied --hosts path
	if err != nil {
		return nil, fmt.Errorf("--hosts %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	out := make([]netip.Addr, 0, 64)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	lineno := 0
	for scanner.Scan() {
		lineno++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		// Strip an inline comment.
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = strings.TrimSpace(raw[:i])
		}
		// Tolerate operator pasting host:port, we only need
		// the host half here (discover supplies its own port
		// list).
		if i := strings.LastIndexByte(raw, ':'); i >= 0 && !strings.Contains(raw, "::") {
			// IPv4 host:port, strip the port.
			raw = raw[:i]
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("--hosts %s line %d: %w", path, lineno, err)
		}
		out = append(out, addr)
		if maxHosts > 0 && len(out) >= maxHosts {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("--hosts %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--hosts %s: no hosts parsed (file empty or all comments)", path)
	}
	return out, nil
}

// discoverHit is one responsive (host, port) pair plus the
// plugin name(s) that claim the port. Multiple plugins can
// share a port (rare but legal, e.g. IEC 61850 MMS shares
// port 102 with S7); operators see all candidates.
type discoverHit struct {
	Address       string   `json:"address"`
	Port          int      `json:"port"`
	ProtocolHints []string `json:"protocol_hints"`
	LatencyMS     int64    `json:"latency_ms"`
}

// pluginPort is one entry in the auto-discover port-list.
// Multiple plugins on the same port produce multiple entries
// (we emit them all in ProtocolHints).
type pluginPort struct {
	Port     int
	PluginID string
}

// registeredPluginPorts returns the unique well-known ports
// across every plugin in core.RegisteredPlugins. Ports are
// returned in ascending order; same-port collisions list
// every claiming plugin.
func registeredPluginPorts() []pluginPort {
	plugins := core.RegisteredPlugins()
	out := make([]pluginPort, 0, len(plugins))
	for _, p := range plugins {
		if p.DefaultPort == 0 {
			continue
		}
		out = append(out, pluginPort{
			Port:     int(p.DefaultPort),
			PluginID: p.Name,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].PluginID < out[j].PluginID
	})
	return out
}

// expandCIDR parses cidr and returns the addresses inside it,
// bounded by maxHosts. For prefixes with the network bit
// (host-zero) and broadcast bit (host-all-ones), we still emit
// them the TCP-connect probe quickly fails for non-routable
// addresses, and trimming them is more error-prone than just
// trying. Honours both IPv4 and IPv6 prefixes.
func expandCIDR(cidr string, maxHosts int) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("--auto %q: %w", cidr, err)
	}
	prefix = prefix.Masked()
	out := make([]netip.Addr, 0, 256)
	addr := prefix.Addr()
	for prefix.Contains(addr) {
		if maxHosts > 0 && len(out) >= maxHosts {
			break
		}
		out = append(out, addr)
		next := addr.Next()
		if !next.IsValid() {
			break
		}
		addr = next
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--auto %q: empty prefix", cidr)
	}
	return out, nil
}

// sweepPace bounds a sweep: parallel connects overall, the pacer per
// host, and an optional overall connect rate.
type sweepPace struct {
	parallel   int
	pacer      *scanner.HostPacer
	ratePerSec int
}

// sweep is sweepPaced with no per-host bound beyond parallel and no
// rate (the pace before 2026-10-21, kept for tests of the dial logic).
func sweep(ctx context.Context, hosts []netip.Addr, ports []pluginPort, parallel int, dialTimeout time.Duration) []discoverHit {
	return sweepPaced(ctx, hosts, ports, dialTimeout, sweepPace{parallel: parallel, pacer: scanner.NewHostPacer(parallel, 0)})
}

// sweepPaced does a parallel TCP-connect probe of every (host, port)
// combination and returns the responsive subset. Jobs go out port by
// port across the hosts, so the workers spread over hosts; each
// connect first takes the host's pacer slot and, with a rate, a token.
func sweepPaced(ctx context.Context, hosts []netip.Addr, ports []pluginPort, dialTimeout time.Duration, pace sweepPace) []discoverHit {
	parallel := pace.parallel
	var limiter *rate.Limiter
	if pace.ratePerSec > 0 {
		limiter = rate.NewLimiter(rate.Limit(pace.ratePerSec), pace.ratePerSec)
	}
	type job struct {
		addr netip.Addr
		port int
	}
	jobs := make(chan job)
	hits := make(chan discoverHit, parallel)
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: dialTimeout}
			for j := range jobs {
				if limiter != nil && limiter.Wait(ctx) != nil {
					continue
				}
				if latency, ok := pacedDial(ctx, dialer, pace.pacer, j.addr, j.port); ok {
					hits <- discoverHit{
						Address:       j.addr.String(),
						Port:          j.port,
						ProtocolHints: pluginsForPort(ports, j.port),
						LatencyMS:     latency,
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, port := range uniquePorts(ports) {
			for _, h := range hosts {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{addr: h, port: port}:
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(hits)
	}()
	out := make([]discoverHit, 0, 64)
	for h := range hits {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// pacedDial takes the host's pacer slot, connects and closes. It
// reports whether the port answered and how long the connect took.
func pacedDial(ctx context.Context, dialer *net.Dialer, pacer *scanner.HostPacer, addr netip.Addr, port int) (int64, bool) {
	release, err := pacer.Acquire(ctx, addr.String())
	if err != nil {
		return 0, false
	}
	start := time.Now()
	// #nosec G115, port comes from registeredPluginPorts which validates against core.Port (uint16 range).
	conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(port)).String())
	release()
	if err != nil {
		return 0, false
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds(), true
}

// uniquePorts returns each port of ports once, in ascending order. A
// port several plugins claim (5007: slmp and melsoft; 102: s7 and mms)
// is dialled once and its hit carries every plugin as a hint; until
// 2026-10-21 it was dialled once per plugin and reported once per
// plugin, each line with the same hints.
func uniquePorts(ports []pluginPort) []int {
	seen := make(map[int]bool, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if !seen[p.Port] {
			seen[p.Port] = true
			out = append(out, p.Port)
		}
	}
	sort.Ints(out)
	return out
}

// pluginsForPort returns the plugin names that claim the
// given port. Multiple matches are common for shared ports
// (e.g. IEC 61850 MMS + S7 both on 102).
func pluginsForPort(ports []pluginPort, port int) []string {
	var out []string
	for _, p := range ports {
		if p.Port == port {
			out = append(out, p.PluginID)
		}
	}
	return out
}

// emitDiscoverResults writes the sweep output in the requested
// format. ndjson is the default (one JSON object per line);
// list emits "host:port" pairs (pipe-friendly with
// `elsereno scan --input list:-`).
func emitDiscoverResults(stdout, stderr io.Writer, hits []discoverHit, format string) error {
	switch format {
	case "list":
		for _, h := range hits {
			// #nosec G115, h.Port comes from a discoverHit produced by sweep, where port was already validated against the registry's uint16 range.
			ap := netip.AddrPortFrom(netip.MustParseAddr(h.Address), uint16(h.Port))
			if _, err := fmt.Fprintln(stdout, ap.String()); err != nil {
				return err
			}
		}
	case "", "ndjson":
		enc := json.NewEncoder(stdout)
		for _, h := range hits {
			if err := enc.Encode(h); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("--format %q: must be ndjson or list", format)
	}
	if _, err := fmt.Fprintf(stderr, "discover: %d responsive (host, port) pairs\n", len(hits)); err != nil {
		return err
	}
	return nil
}

// guard against an unused-os import on minimal builds.
var _ = os.Stdout

// describeGapRate renders the per-host pause and the overall rate of a
// pace for the start-of-run line.
func describeGapRate(p pacing) string {
	gap := "no pause between connects to a host"
	if p.interval > 0 {
		gap = p.interval.String() + " between connects to a host"
	}
	if p.ratePerSec > 0 {
		return fmt.Sprintf("%s, %d connects/s overall", gap, p.ratePerSec)
	}
	return gap
}
