package netutil_test

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/netutil"
)

// A Read blocked on a silent peer returns soon after the context is
// cancelled, not when the connection's own deadline passes.
func TestCloseOnDoneInterruptsBlockedRead(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	_ = client.SetDeadline(time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	done := netutil.CloseOnDone(ctx, client)
	defer done()

	errc := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Read returned no error after cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read still blocked 2s after cancel")
	}
}

type countCloser struct{ n int }

func (c *countCloser) Close() error { c.n++; return nil }

// The returned function closes the connection, and once it has run a
// later cancel does nothing more.
func TestCloseOnDoneReturnedFuncCloses(t *testing.T) {
	t.Parallel()
	c := &countCloser{}
	ctx, cancel := context.WithCancel(context.Background())
	netutil.CloseOnDone(ctx, c)()
	cancel()
	time.Sleep(10 * time.Millisecond)
	if c.n != 1 {
		t.Fatalf("Close called %d times, want 1", c.n)
	}
}
