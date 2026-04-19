package proxy_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/proxy"
)

// echoHandler is a trivial test handler that copies client <->
// upstream both ways.
type echoHandler struct{}

func (echoHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	errs := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, client); errs <- err }()
	go func() { _, err := io.Copy(client, upstream); errs <- err }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

// echoSrv is an upstream TCP server that echoes everything it reads.
func echoSrv(t *testing.T) *net.TCPAddr {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return addr
}

func TestServerEndToEnd(t *testing.T) {
	t.Parallel()

	upstream := echoSrv(t)

	srv, err := proxy.New(proxy.Options{
		Listen:   "127.0.0.1:0",
		Upstream: upstream.String(),
		Handler:  echoHandler{},
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

	// Wait for the listener.
	for i := 0; i < 50 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("listener never bound")
	}

	d := net.Dialer{Timeout: 1 * time.Second}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer dialCancel()
	c, err := d.DialContext(dialCtx, "tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := c.Write([]byte("hello world\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "hello world\n" {
		t.Fatalf("echo mismatch: %q", got)
	}
	cancel()
	<-done
}

func TestLoggingHookRecords(t *testing.T) {
	t.Parallel()

	upstream := echoSrv(t)
	var log bytes.Buffer

	srv, err := proxy.New(proxy.Options{
		Listen:   "127.0.0.1:0",
		Upstream: upstream.String(),
		Handler:  echoHandler{},
		Hook:     proxy.LoggingHook{W: &log},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	for i := 0; i < 50 && srv.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	d2 := net.Dialer{Timeout: 1 * time.Second}
	dialCtx2, dialCancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer dialCancel2()
	c, err := d2.DialContext(dialCtx2, "tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(1 * time.Second))
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 16)
	_, _ = c.Read(buf)

	time.Sleep(50 * time.Millisecond)
	body := log.String()
	if !bytes.Contains([]byte(body), []byte("bytes:")) {
		t.Fatalf("logging hook produced no output: %q", body)
	}
}
