package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/core"
)

// TestNoPluginConfirmsAReflectedProbe probes every registered plugin twice,
// once against a loopback server that reflects whatever it receives (an echo
// service) and once against one that answers with fixed junk, and fails if
// any plugin scores a higher capability for the reflection than for the junk.
// A reflected probe is not a device, so it must be classified like any other
// unrecognised reply. The 2026-10-07 audit found ten plugins whose classifier
// accepted a signature their own request also carries (PITF-071, PITF-072);
// this keeps a new plugin from reintroducing the class.
//
// Junk, not silence, is the reference: several plugins score "no reply"
// lower than "an unrecognised reply" (xot: 0 vs 30), which is not a false
// positive. The junk is plain text carrying no plugin's signature or banner.
//
// Limits: a plugin whose capability does not depend on the reply (modbus
// keeps 60) cannot fail this check, and a plugin that errors against a plain
// loopback server (HTTP/TLS plugins, AT modem, MQTT) is skipped and logged.
func TestNoPluginConfirmsAReflectedProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("probes every plugin over loopback; skipped in -short")
	}
	echoPort := dualLoopbackServer(t, true)
	junkPort := dualLoopbackServer(t, false)

	type result struct {
		echo, junk     int
		echoOK, junkOK bool
	}
	plugins := core.RegisteredPlugins()
	results := make([]result, len(plugins))
	var wg sync.WaitGroup
	for i, p := range plugins {
		wg.Add(2)
		go func(i int, p core.Plugin) {
			defer wg.Done()
			results[i].echo, results[i].echoOK = probeCapability(p, echoPort)
		}(i, p)
		go func(i int, p core.Plugin) {
			defer wg.Done()
			results[i].junk, results[i].junkOK = probeCapability(p, junkPort)
		}(i, p)
	}
	wg.Wait()

	compared := 0
	for i, p := range plugins {
		r := results[i]
		if !r.echoOK || !r.junkOK {
			t.Logf("%s: skipped (no finding against a plain loopback server)", p.Name)
			continue
		}
		compared++
		if r.echo > r.junk {
			t.Errorf("%s confirms a reflected probe: capability %d against an echo server vs %d for an unrecognised (junk) reply (PITF-071)",
				p.Name, r.echo, r.junk)
		}
	}
	// Guard the guard: if binding or probing broke, everything would be
	// skipped and the test would pass vacuously.
	if compared < 25 {
		t.Fatalf("only %d of %d plugins produced a comparable finding; expected at least 25", compared, len(plugins))
	}
}

// probeCapability runs one plugin's Probe against a loopback port and
// returns the finding's capability factor (false when the probe errored or
// produced no finding).
func probeCapability(p core.Plugin, port core.Port) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f, err := p.Factory().Probe(ctx, core.Target{
		Address: netip.MustParseAddr("127.0.0.1"),
		Port:    port,
	})
	if err != nil || f == nil {
		return 0, false
	}
	c, ok := f.Factors["capability"]
	return c, ok
}

// junkReply is the reference "unrecognised reply": plain text that carries
// no plugin's signature, magic or banner.
var junkReply = []byte("elsereno-guard: this is not a protocol reply\n")

// dualLoopbackServer serves TCP and UDP on the same loopback port, so a
// probe reaches it whichever transport its plugin speaks. echo reflects
// every byte back; otherwise it answers each probe with junkReply.
func dualLoopbackServer(t *testing.T, echo bool) core.Port {
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
			continue // UDP side of that port number is taken; pick another
		}
		t.Cleanup(func() { _ = tl.Close(); _ = ul.Close() })
		go serveTCP(tl, echo)
		go serveUDP(ul, echo)
		return core.Port(uint16(addr.Port)) // #nosec G115 -- range-checked above.
	}
	t.Fatal("could not bind TCP and UDP on one loopback port")
	return 0
}

func serveTCP(l net.Listener, echo bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			if echo {
				_, _ = io.Copy(c, c)
				return
			}
			// Junk: take the probe, answer junkReply, close (closing gives
			// multi-step probes a clean finding instead of a timeout).
			if _, err := c.Read(make([]byte, 65536)); err == nil {
				_, _ = c.Write(junkReply)
			}
		}(c)
	}
}

func serveUDP(c net.PacketConn, echo bool) {
	buf := make([]byte, 65536)
	for {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		reply := junkReply
		if echo {
			reply = buf[:n]
		}
		_, _ = c.WriteTo(reply, addr)
	}
}
