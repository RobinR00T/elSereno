package scanner

import (
	"net/netip"

	"local/elsereno/internal/core"
)

// Dedupe returns a slice with duplicate (address, port) tuples
// removed. IPv4-mapped IPv6 addresses are normalised via .Unmap() so
// "::ffff:1.2.3.4" and "1.2.3.4" collapse. Order of first appearance
// is preserved.
func Dedupe(in []core.Target) []core.Target {
	seen := make(map[tupleKey]struct{}, len(in))
	out := make([]core.Target, 0, len(in))
	for _, t := range in {
		k := keyOf(t)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		t.Address = t.Address.Unmap()
		out = append(out, t)
	}
	return out
}

type tupleKey struct {
	addr netip.Addr
	port core.Port
}

func keyOf(t core.Target) tupleKey {
	return tupleKey{addr: t.Address.Unmap(), port: t.Port}
}
