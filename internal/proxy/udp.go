package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// maxUDPDatagram caps a single read from the UDP listener. 65535 is
// the IPv4 UDP payload ceiling; real ICS datagrams are far smaller,
// but the buffer must never truncate a legitimate one.
const maxUDPDatagram = 65535

// runUDP is the datagram counterpart to the TCP accept loop. It binds
// one UDP socket and, for each distinct client source address, spins
// up a session: a freshly dialled upstream UDP socket plus a
// per-source client adapter, both handed to the same
// Handler.Handle(ctx, client, upstream) contract. Each client Read
// yields exactly one datagram; each client Write sends one datagram
// back to that source via the shared listener.
func (s *Server) runUDP(ctx context.Context) error {
	lc := &net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", s.opts.Listen)
	if err != nil {
		return fmt.Errorf("proxy: listen udp %s: %w", s.opts.Listen, err)
	}
	s.lnMu.Lock()
	s.pc = pc
	s.lnMu.Unlock()

	go func() {
		<-ctx.Done()
		s.stopped.Store(true)
		_ = pc.Close()
	}()

	var mu sync.Mutex
	sessions := make(map[string]*udpSession)
	buf := make([]byte, maxUDPDatagram)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.stopped.Load() {
				break
			}
			return fmt.Errorf("proxy: udp read: %w", err)
		}
		key := addr.String()
		mu.Lock()
		sess := sessions[key]
		if sess == nil {
			if s.opts.MaxConns > 0 && int64(len(sessions)) >= int64(s.opts.MaxConns) {
				mu.Unlock()
				continue
			}
			sess = s.newUDPSession(ctx, pc, addr, func() {
				mu.Lock()
				delete(sessions, key)
				mu.Unlock()
			})
			if sess == nil {
				mu.Unlock()
				continue // upstream dial failed; drop the datagram
			}
			sessions[key] = sess
		}
		mu.Unlock()

		datagram := make([]byte, n)
		copy(datagram, buf[:n])
		sess.deliver(datagram)
	}
	s.wg.Wait()
	return ctx.Err()
}

// newUDPSession dials the upstream and starts the handler for a new
// client source address. Returns nil if the upstream dial fails.
func (s *Server) newUDPSession(ctx context.Context, pc net.PacketConn, addr net.Addr, onClose func()) *udpSession {
	dialer := net.Dialer{Timeout: s.opts.DialTimeout}
	upstream, err := dialer.DialContext(ctx, "udp", s.opts.Upstream)
	if err != nil {
		return nil
	}
	sctx, cancel := context.WithCancel(ctx)
	client := &udpClientConn{pc: pc, addr: addr, in: make(chan []byte, 64), ctx: sctx}
	sess := &udpSession{
		in:          client.in,
		cancel:      cancel,
		idleTimeout: s.opts.IdleTimeout,
	}
	// Idle watchdog: a UDP client has no FIN, so no client datagram
	// for IdleTimeout tears the session down.
	sess.idle = time.AfterFunc(s.opts.IdleTimeout, cancel)

	s.wg.Add(1)
	s.active.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.active.Add(-1)
		defer onClose()
		defer sess.idle.Stop()
		defer cancel()
		defer func() { _ = upstream.Close() }()
		_ = s.opts.Handler.Handle(sctx, client, upstream)
	}()
	return sess
}

// udpSession tracks one client-source-address flow.
type udpSession struct {
	in          chan []byte
	cancel      context.CancelFunc
	idle        *time.Timer
	idleTimeout time.Duration
}

// deliver hands one client datagram to the session and resets the
// idle timer. A full buffer drops the datagram rather than blocking
// the shared read loop, so one slow session can't stall the others.
func (sess *udpSession) deliver(datagram []byte) {
	sess.idle.Reset(sess.idleTimeout)
	select {
	case sess.in <- datagram:
	default:
	}
}

// udpClientConn adapts one client source address to the io.ReadWriter
// the Handler expects. Read returns one buffered datagram at a time;
// Write sends one datagram back to that source through the shared
// listener (net.PacketConn.WriteTo is safe for concurrent use, so
// sessions can write independently).
type udpClientConn struct {
	pc   net.PacketConn
	addr net.Addr
	in   chan []byte
	ctx  context.Context //nolint:containedctx // scoped to the session lifetime
}

// Read returns the next datagram, or io.EOF once the session context
// is cancelled (idle timeout, upstream error, or shutdown).
func (c *udpClientConn) Read(p []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, io.EOF
	case data := <-c.in:
		return copy(p, data), nil
	}
}

// Write sends p as a single datagram to the client source address.
func (c *udpClientConn) Write(p []byte) (int, error) {
	if _, err := c.pc.WriteTo(p, c.addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Ensure the adapter satisfies io.ReadWriter.
var _ io.ReadWriter = (*udpClientConn)(nil)
