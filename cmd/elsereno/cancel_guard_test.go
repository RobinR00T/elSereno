package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/core"
)

// TestEveryPluginStopsOnCancel probes every registered plugin against a
// loopback server that accepts and then says nothing, cancels the context
// shortly after, and fails if a probe is still running a second later.
// Plugins set a fixed IO deadline (3 to 5 s) after dialling; until
// 2026-10-21 that deadline ignored the context, so Ctrl-C or a dashboard
// job cancel waited for it on every probe in flight. netutil.CloseOnDone
// closes the connection when the context is done.
func TestEveryPluginStopsOnCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("probes every plugin over loopback; skipped in -short")
	}
	port := silentLoopbackServer(t)
	const cancelAfter = 150 * time.Millisecond
	const limit = cancelAfter + time.Second
	plugins := core.RegisteredPlugins()
	took := make([]time.Duration, len(plugins))
	var wg sync.WaitGroup
	for i, p := range plugins {
		wg.Add(1)
		go func(i int, p core.Plugin) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			time.AfterFunc(cancelAfter, cancel)
			start := time.Now()
			_, _ = p.Factory().Probe(ctx, core.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: port})
			took[i] = time.Since(start)
		}(i, p)
	}
	wg.Wait()
	blocked := 0
	for i, p := range plugins {
		if took[i] >= cancelAfter-10*time.Millisecond {
			blocked++
		}
		if took[i] > limit {
			t.Errorf("%s: Probe returned %v after start, %v after cancel; want within %v of cancel",
				p.Name, took[i].Round(time.Millisecond), (took[i] - cancelAfter).Round(time.Millisecond), limit-cancelAfter)
		}
	}
	// Guard the guard: a probe that fails before the cancel (bind or dial
	// broke) proves nothing, and if most did the test would pass vacuously.
	if blocked < 25 {
		t.Fatalf("only %d of %d plugins were still waiting on the silent server when the context was cancelled; expected at least 25", blocked, len(plugins))
	}
}

// silentLoopbackServer serves TCP and UDP on one loopback port and never
// answers: TCP connections are accepted and held open, datagrams are read
// and dropped.
func silentLoopbackServer(t *testing.T) core.Port {
	t.Helper()
	lc := net.ListenConfig{}
	for attempt := 0; attempt < 20; attempt++ {
		tl, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		addr, ok := tl.Addr().(*net.TCPAddr)
		if !ok || addr.Port <= 0 || addr.Port > 0xFFFF {
			_ = tl.Close()
			t.Fatalf("unexpected tcp listener address %v", tl.Addr())
		}
		ul, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:"+strconv.Itoa(addr.Port))
		if err != nil {
			_ = tl.Close()
			continue
		}
		var mu sync.Mutex
		var held []net.Conn
		t.Cleanup(func() {
			_ = tl.Close()
			_ = ul.Close()
			mu.Lock()
			for _, c := range held {
				_ = c.Close()
			}
			mu.Unlock()
		})
		go func() {
			for {
				c, err := tl.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				held = append(held, c)
				mu.Unlock()
			}
		}()
		go func() {
			buf := make([]byte, 65536)
			for {
				if _, _, err := ul.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
		return core.Port(uint16(addr.Port)) // #nosec G115 -- range-checked above.
	}
	t.Fatal("could not bind TCP and UDP on one loopback port")
	return 0
}
