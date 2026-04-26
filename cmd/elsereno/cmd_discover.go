package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
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
		maxHosts     int
		dialTimeout  time.Duration
		parallel     int
		outputFormat string
	)
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Sweep a CIDR for ports of every registered plugin",
		Long: `discover --auto <CIDR> performs a TCP-connect sweep
of the well-known ports of every registered ElSereno plugin
across the supplied CIDR. Responsive (host, port) pairs are
emitted to stdout as NDJSON; the operator pipes the output
into ` + "`elsereno scan --input list:-`" + ` for protocol-aware
fingerprinting on the responsive subset.

Goal: skip the manual port-list maintenance step. The operator
points at a CIDR, gets a "what's actually listening" inventory
in one command, and the deep-scan phase only runs against
hosts that responded.

The walk is bounded by --max-hosts (default 256, i.e. /24
sized) and --parallel (default 64 concurrent connects). Use
--dial-timeout to tune for slow links.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if auto == "" {
				return fail(core.ExitUsage, errors.New("--auto <CIDR> is required (e.g. --auto 192.168.1.0/24)"))
			}
			ports := registeredPluginPorts()
			if len(ports) == 0 {
				return fail(core.ExitSoftware, errors.New("no plugins registered — link with the protocol packages"))
			}
			hosts, err := expandCIDR(auto, maxHosts)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			ctx := cmd.Context()
			results := sweep(ctx, hosts, ports, parallel, dialTimeout)
			return emitDiscoverResults(cmd.OutOrStdout(), cmd.ErrOrStderr(), results, outputFormat)
		},
	}
	cmd.Flags().StringVar(&auto, "auto", "", "CIDR to sweep (e.g. 192.168.1.0/24)")
	cmd.Flags().IntVar(&maxHosts, "max-hosts", discoverDefaultMaxHosts, "cap on CIDR addresses walked")
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", discoverDefaultDialTimeout, "per-(host, port) TCP-connect timeout")
	cmd.Flags().IntVar(&parallel, "parallel", discoverDefaultParallel, "max concurrent TCP-connects")
	cmd.Flags().StringVar(&outputFormat, "format", "ndjson", "output format: ndjson | list (host:port one per line)")
	return cmd
}

// discoverHit is one responsive (host, port) pair plus the
// plugin name(s) that claim the port. Multiple plugins can
// share a port (rare but legal — e.g. IEC 61850 MMS shares
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
// them — the TCP-connect probe quickly fails for non-routable
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

// sweep does a parallel TCP-connect probe of every (host, port)
// combination, bounded by parallel concurrency. Returns the
// responsive subset.
func sweep(ctx context.Context, hosts []netip.Addr, ports []pluginPort, parallel int, dialTimeout time.Duration) []discoverHit {
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
				start := time.Now()
				// #nosec G115 — j.port comes from registeredPluginPorts which validates against core.Port (uint16 range).
				addrPort := netip.AddrPortFrom(j.addr, uint16(j.port))
				conn, err := dialer.DialContext(ctx, "tcp", addrPort.String())
				if err != nil {
					continue
				}
				_ = conn.Close()
				latency := time.Since(start).Milliseconds()
				hits <- discoverHit{
					Address:       j.addr.String(),
					Port:          j.port,
					ProtocolHints: pluginsForPort(ports, j.port),
					LatencyMS:     latency,
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, h := range hosts {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- job{addr: h, port: p.Port}:
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
			// #nosec G115 — h.Port comes from a discoverHit produced by sweep, where port was already validated against the registry's uint16 range.
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
