package proxy_test

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/proxy"
)

// udpEchoSrv is an upstream UDP server that echoes every datagram
// back to its sender.
func udpEchoSrv(t *testing.T) *net.UDPAddr {
	t.Helper()
	lc := &net.ListenConfig{}
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("addr type %T", pc.LocalAddr())
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], src)
		}
	}()
	return addr
}

func TestServerUDPEndToEnd(t *testing.T) {
	t.Parallel()

	upstream := udpEchoSrv(t)

	srv, err := proxy.New(proxy.Options{
		Listen:   "127.0.0.1:0",
		Upstream: upstream.String(),
		Handler:  echoHandler{},
		Network:  "udp",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()

	for i := 0; i < 50 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("listener never bound")
	}
	if got := srv.Addr().Network(); got != "udp" {
		t.Fatalf("Addr().Network() = %q, want udp", got)
	}

	c, err := net.Dial("udp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	// Two datagrams on the same source address share one session; both
	// must round-trip through the upstream echo and come back intact.
	for _, want := range []string{"ping-one", "ping-two-longer-datagram"} {
		if _, err := c.Write([]byte(want)); err != nil {
			t.Fatalf("write %q: %v", want, err)
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read for %q: %v", want, err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("echo mismatch: got %q want %q", got, want)
		}
	}

	cancel()
	<-done
}

func TestNewRejectsUnsupportedNetwork(t *testing.T) {
	t.Parallel()
	if _, err := proxy.New(proxy.Options{
		Listen:   "127.0.0.1:0",
		Upstream: "127.0.0.1:1",
		Handler:  echoHandler{},
		Network:  "sctp",
	}); err == nil {
		t.Fatal("New accepted an unsupported network")
	}
}
