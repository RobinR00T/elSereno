package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/idna"

	"local/elsereno/internal/core"
)

// Resolver turns a hostname (with IDN-aware normalisation) or a literal
// address into one or more core.Target values. Each (address, port)
// tuple is emitted; callers hand the stream to Dedupe before probing.
type Resolver struct {
	// Resolver can be swapped in tests. When nil, net.DefaultResolver
	// is used.
	Resolver *net.Resolver
}

// Resolve returns the full set of (address, port) pairs for `host` and
// `port`. Hostnames resolve to every A and AAAA record; literal IPs
// return themselves. IDNs are converted via x/net/idna.Lookup.ToASCII
// before resolution (ADR conventions.md).
func (r Resolver) Resolve(ctx context.Context, host string, port core.Port) ([]core.Target, error) {
	// Literal IP fast path.
	if addr, err := netip.ParseAddr(host); err == nil {
		return []core.Target{{Address: addr, Port: port}}, nil
	}

	normalised, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return nil, fmt.Errorf("scanner: IDN %q: %w", host, err)
	}

	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupNetIP(ctx, "ip", normalised)
	if err != nil {
		return nil, fmt.Errorf("scanner: lookup %q: %w", normalised, err)
	}

	out := make([]core.Target, 0, len(ips))
	for _, ip := range ips {
		out = append(out, core.Target{Address: ip.Unmap(), Port: port})
	}
	return out, nil
}
