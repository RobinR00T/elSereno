package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"local/elsereno/internal/core"
)

// Direction identifies which side of the proxy a byte chunk came
// from.
type Direction int

// Direction values.
const (
	// ClientToUpstream means the frame was produced by the originator
	// that connected to the proxy.
	ClientToUpstream Direction = iota
	// UpstreamToClient means the frame was produced by the remote
	// device the proxy is forwarding to.
	UpstreamToClient
)

// Hook is the interface plugins implement when they want to observe
// (or mutate) traffic the framework forwards.
type Hook interface {
	// PreHook runs before the bytes are forwarded. Returning a
	// replacement slice lets the hook rewrite; returning nil leaves
	// the original unchanged. Returning an error aborts the session.
	PreHook(ctx context.Context, dir Direction, b []byte) ([]byte, error)

	// PostHook runs after the bytes have been forwarded (or dropped
	// by PreHook returning []). It is purely observational.
	PostHook(ctx context.Context, dir Direction, b []byte)
}

// NoopHook is a Hook that does nothing. Plugins without observation
// needs can embed it.
type NoopHook struct{}

// PreHook implements Hook.
func (NoopHook) PreHook(_ context.Context, _ Direction, _ []byte) ([]byte, error) {
	return nil, nil
}

// PostHook implements Hook.
func (NoopHook) PostHook(_ context.Context, _ Direction, _ []byte) {}

// Options configures a Server.
type Options struct {
	// Listen is the bind address (e.g. "127.0.0.1:1502"). Required.
	Listen string

	// Upstream is the device the proxy forwards to. Required.
	Upstream string

	// Handler is the protocol-specific handler the framework invokes
	// once both sockets are connected. Required.
	Handler core.ProxyHandler

	// DialTimeout caps upstream dial. Default 5 s.
	DialTimeout time.Duration

	// IdleTimeout disconnects clients with no activity for this long.
	// Default 120 s.
	IdleTimeout time.Duration

	// MaxConns caps concurrent client connections. 0 means unlimited.
	MaxConns int

	// Hook runs before/after each io.Copy byte-chunk. Optional.
	Hook Hook
}

// Server wraps a net.Listener and runs the accept/dial/hook loop.
type Server struct {
	opts    Options
	lnMu    sync.RWMutex
	ln      net.Listener
	wg      sync.WaitGroup
	active  atomic.Int64
	stopped atomic.Bool
}

// New constructs a Server. Fills in defaults for timeouts.
func New(opts Options) (*Server, error) {
	if opts.Listen == "" {
		return nil, errors.New("proxy: Listen is required")
	}
	if opts.Upstream == "" {
		return nil, errors.New("proxy: Upstream is required")
	}
	if opts.Handler == nil {
		return nil, errors.New("proxy: Handler is required")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 120 * time.Second
	}
	if opts.Hook == nil {
		opts.Hook = NoopHook{}
	}
	return &Server{opts: opts}, nil
}

// Run binds the listener and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.opts.Listen)
	if err != nil {
		return fmt.Errorf("proxy: listen %s: %w", s.opts.Listen, err)
	}
	s.lnMu.Lock()
	s.ln = ln
	s.lnMu.Unlock()

	go func() {
		<-ctx.Done()
		s.stopped.Store(true)
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.stopped.Load() {
				break
			}
			return fmt.Errorf("proxy: accept: %w", err)
		}
		if s.opts.MaxConns > 0 && s.active.Load() >= int64(s.opts.MaxConns) {
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		s.active.Add(1)
		go s.handle(ctx, conn)
	}
	s.wg.Wait()
	return ctx.Err()
}

// Addr returns the listener address (useful for tests with :0).
func (s *Server) Addr() net.Addr {
	s.lnMu.RLock()
	defer s.lnMu.RUnlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer s.wg.Done()
	defer s.active.Add(-1)
	defer func() { _ = client.Close() }()

	d := net.Dialer{Timeout: s.opts.DialTimeout}
	upstream, err := d.DialContext(ctx, "tcp", s.opts.Upstream)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	// Set idle deadlines.
	bumpDeadline := func() {
		dl := time.Now().Add(s.opts.IdleTimeout)
		_ = client.SetDeadline(dl)
		_ = upstream.SetDeadline(dl)
	}
	bumpDeadline()

	// Wrap both sides so hook chains run on every byte chunk.
	clientRW := &hookedRW{
		under:  client,
		hook:   s.opts.Hook,
		dir:    ClientToUpstream,
		ctx:    ctx,
		update: bumpDeadline,
	}
	upstreamRW := &hookedRW{
		under:  upstream,
		hook:   s.opts.Hook,
		dir:    UpstreamToClient,
		ctx:    ctx,
		update: bumpDeadline,
	}

	_ = s.opts.Handler.Handle(ctx, clientRW, upstreamRW)
}

// hookedRW wraps a net.Conn. Read calls run through PreHook /
// PostHook so the framework sees bytes before they reach the
// handler.
type hookedRW struct {
	under  net.Conn
	hook   Hook
	dir    Direction
	ctx    context.Context //nolint:containedctx // scoped to connection lifetime
	update func()
	buf    []byte
}

// Read implements io.Reader.
func (h *hookedRW) Read(p []byte) (int, error) {
	if len(h.buf) > 0 {
		n := copy(p, h.buf)
		h.buf = h.buf[n:]
		return n, nil
	}
	n, err := h.under.Read(p)
	if n > 0 {
		h.update()
		replacement, hookErr := h.hook.PreHook(h.ctx, h.dir, p[:n])
		if hookErr != nil {
			return 0, hookErr
		}
		if replacement != nil {
			copy(p, replacement)
			m := len(replacement)
			if m > n {
				// Overflow into next Read call.
				copy(p, replacement[:n])
				h.buf = append(h.buf, replacement[n:]...)
				return n, err
			}
			n = m
		}
		h.hook.PostHook(h.ctx, h.dir, p[:n])
	}
	return n, err
}

// Write implements io.Writer.
func (h *hookedRW) Write(p []byte) (int, error) {
	h.update()
	return h.under.Write(p)
}

// Close implements io.Closer when the handler wants to tear the
// per-side connection early.
func (h *hookedRW) Close() error { return h.under.Close() }

// Ensure hookedRW satisfies io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*hookedRW)(nil)
