package banner

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
)

// TestProbe_IDDependsOnTarget: two silent ports must not share a finding
// ID (the ID hashed only the banner bytes until 2026-10-07).
func TestProbe_IDDependsOnTarget(t *testing.T) {
	t.Parallel()
	ids := map[core.UUID]bool{}
	for i := 0; i < 2; i++ {
		lc := net.ListenConfig{}
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("identical banner\r\n"))
			_ = c.Close()
		}()
		addr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			t.Fatalf("listener address %T", ln.Addr())
		}
		p := Default()
		p.ReadTimeout = time.Second
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		f, err := p.Probe(ctx, core.Target{Address: addr.AddrPort().Addr(), Port: core.Port(uint16(addr.Port))}) // #nosec G115 -- listener port fits.
		cancel()
		if err != nil {
			t.Fatalf("Probe: %v", err)
		}
		ids[f.ID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("two targets with the same banner got %d distinct IDs, want 2", len(ids))
	}
}
