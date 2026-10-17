//go:build !mini

package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
)

// countingListener accepts and closes connections on 127.0.0.1 and
// counts them. stop closes it and waits, so the count is final.
func countingListener(t *testing.T) (addr string, accepted *atomic.Int32, stop func()) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), &n, func() { _ = ln.Close(); <-done }
}
