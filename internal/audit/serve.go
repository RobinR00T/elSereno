package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Server is the cross-process audit daemon. It wraps a Writer
// (typically a FileWriter pointing at ~/.elsereno/audit.jsonl)
// and listens on a Unix domain socket. Other elsereno processes
// connect via Client and fan-in audit Entries through this
// single serialised writer.
//
// Why a daemon (vs the v1.15-chunk-4 flock):
//
//   - flock serialises but every emitter takes the lock + reads
//     the tail to resume the chain on every Append. With N
//     emitters, that's N tail-reads per N appends — fine for
//     2-3 processes but wastes I/O at SOC scale.
//   - The daemon holds the FileWriter once, computes prev_hash
//     in memory for every append, and writes once. Emitters
//     just send JSON over the socket.
//
// Protocol on the wire is line-delimited JSON (one Request per
// line, one Response per line). Easy to drive from `nc -U` for
// debugging and lets the daemon multiplex many concurrent
// emitters over independent connections without contention
// inside each connection.
//
// Mode + ownership: the socket file is created with mode 0600
// + owned by the operator user. Cross-user fan-in is not in
// scope; that's a multi-user OIDC concern (vNext).
type Server struct {
	w  Writer
	mu sync.Mutex
	ln net.Listener
}

// Request is one inbound message. Only Entry is sent by the
// emitter; the daemon fills the chain-derived fields.
type Request struct {
	// Entry carries OccurredAt / Actor / EventType / Payload.
	// ID, PrevHash, EntryHash are ignored on the wire; the
	// daemon computes them.
	Entry Entry `json:"entry"`
}

// Response is one outbound message. On success, OK=true and
// Entry carries the persisted entry (with ID + PrevHash +
// EntryHash filled). On failure, OK=false and Error has a
// human-readable reason.
type Response struct {
	OK    bool   `json:"ok"`
	Entry Entry  `json:"entry,omitempty"`
	Error string `json:"error,omitempty"`
}

// NewServer prepares a daemon that listens on socketPath. The
// path is created (parent directory must exist) with mode 0600.
// Any existing socket file at the path is removed first so
// crashes don't leave stale sockets behind that block restart.
//
// The returned Server is not yet Serve'ing — call Serve(ctx) to
// accept connections.
func NewServer(w Writer, socketPath string) (*Server, error) {
	if w == nil {
		return nil, errors.New("audit: NewServer: writer is nil")
	}
	if socketPath == "" {
		return nil, errors.New("audit: NewServer: empty socket path")
	}
	// Reject relative paths to avoid daemons that bind in CWD by accident.
	if !filepath.IsAbs(socketPath) {
		return nil, fmt.Errorf("audit: NewServer: socket path %q must be absolute", socketPath)
	}
	// Remove stale socket. Ignore "file does not exist" but not other errors.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("audit: NewServer: clear stale socket %s: %w", socketPath, err)
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("audit: NewServer: listen %s: %w", socketPath, err)
	}
	// Tighten socket file mode — net.Listen leaves it at 0775 typically.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("audit: NewServer: chmod %s: %w", socketPath, err)
	}
	return &Server{w: w, ln: ln}, nil
}

// SocketPath returns the path the server is bound to, useful for
// log lines + tests that need to reconstruct the path.
func (s *Server) SocketPath() string {
	if s.ln == nil {
		return ""
	}
	if a, ok := s.ln.Addr().(*net.UnixAddr); ok {
		return a.Name
	}
	return ""
}

// Close shuts the listener down + removes the socket file. Safe
// to call from a signal handler concurrently with Serve.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	path := s.SocketPath()
	err := s.ln.Close()
	s.ln = nil
	if path != "" {
		_ = os.Remove(path)
	}
	return err
}

// Serve runs the accept loop until ctx is cancelled or the
// listener errors. Each connection is handled in its own
// goroutine. The daemon's Writer mutex serialises chain order
// across all clients.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isClosedListenerErr(err) {
				return nil
			}
			return fmt.Errorf("audit: Serve: accept: %w", err)
		}
		go s.handle(ctx, c)
	}
}

func isClosedListenerErr(err error) bool {
	// net.ErrClosed is the canonical wrapper post-Close; some
	// older Go versions surface a string match instead.
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// Final defensive fallback for the string form.
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}

// handle drives a single connection: read a Request, Append it
// via the wrapped Writer, write a Response. On EOF / read error
// the connection is closed silently — clients can reconnect.
func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	dec := json.NewDecoder(bufio.NewReader(c))
	enc := json.NewEncoder(c)
	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			return
		}
		entry, err := s.w.Append(ctx, req.Entry)
		var resp Response
		if err != nil {
			resp = Response{OK: false, Error: err.Error()}
		} else {
			resp = Response{OK: true, Entry: entry}
		}
		if encErr := enc.Encode(&resp); encErr != nil {
			return
		}
	}
}

// Client is a Writer that submits Entries to a Server over UDS.
// Implements the audit.Writer contract so callers can swap a
// FileWriter for a Client without code changes.
type Client struct {
	socketPath string
	mu         sync.Mutex
	conn       net.Conn
	enc        *json.Encoder
	dec        *json.Decoder
}

// DialClient connects to a Server at socketPath. The connection
// is opened lazily — DialClient just records the path; the
// first Append establishes the socket. This keeps short-lived
// processes that may never need to write audit entries
// (`elsereno doctor`, `version`, etc.) from tripping a missing-
// daemon error at startup.
func DialClient(socketPath string) *Client {
	return &Client{socketPath: socketPath}
}

// Close shuts the underlying connection. Safe to call before any
// Append (no-op when no connection has been established).
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.enc = nil
	c.dec = nil
	return err
}

// Append implements Writer. Sends the entry over the socket and
// blocks until the daemon responds with the persisted form.
// If the connection is dead (daemon restarted, socket removed)
// Append re-dials transparently on the next call. ctx scopes
// the dial; once the connection is established, the read+write
// uses the underlying socket's blocking semantics.
func (c *Client) Append(ctx context.Context, e Entry) (Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		if err := c.dialLocked(ctx); err != nil {
			return Entry{}, err
		}
	}
	if err := c.enc.Encode(&Request{Entry: e}); err != nil {
		// Drop the dead connection; next Append will re-dial.
		_ = c.conn.Close()
		c.conn, c.enc, c.dec = nil, nil, nil
		return Entry{}, fmt.Errorf("audit: client send: %w", err)
	}
	var resp Response
	if err := c.dec.Decode(&resp); err != nil {
		_ = c.conn.Close()
		c.conn, c.enc, c.dec = nil, nil, nil
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Entry{}, fmt.Errorf("audit: client recv: daemon closed connection")
		}
		return Entry{}, fmt.Errorf("audit: client recv: %w", err)
	}
	if !resp.OK {
		return Entry{}, fmt.Errorf("audit: daemon: %s", resp.Error)
	}
	return resp.Entry, nil
}

func (c *Client) dialLocked(ctx context.Context) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("audit: client dial %s: %w", c.socketPath, err)
	}
	c.conn = conn
	c.enc = json.NewEncoder(conn)
	c.dec = json.NewDecoder(bufio.NewReader(conn))
	return nil
}
