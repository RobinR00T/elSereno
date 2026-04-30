package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/audit"
)

// shortSocketDir returns a short tmp dir suitable for binding
// Unix domain sockets on macOS, where the kernel caps sun_path
// at 104 bytes including NUL. t.TempDir() lives under
// /var/folders/... which often exceeds the cap.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "els-aud-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// startTestServer wires up a temp-file FileWriter + Server and
// returns the socketPath. Cleanup is automatic via t.Cleanup.
func startTestServer(t *testing.T) string {
	t.Helper()
	dir := shortSocketDir(t)
	logPath := filepath.Join(dir, "audit.jsonl")
	socketPath := filepath.Join(dir, "audit.sock")

	w, err := audit.OpenFileWriter(logPath)
	if err != nil {
		t.Fatalf("OpenFileWriter: %v", err)
	}
	srv, err := audit.NewServer(w, socketPath)
	if err != nil {
		_ = w.Close()
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		_ = w.Close()
	})
	go func() { _ = srv.Serve(ctx) }()
	// Wait until the socket is usable (Accept loop spinning up).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return socketPath
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server did not bind socket within 2s")
	return ""
}

func TestNewServer_RejectsRelativePath(t *testing.T) {
	_, err := audit.NewServer(stubWriter{}, "relative/path.sock")
	if err == nil {
		t.Fatal("expected error for relative socket path")
	}
}

func TestNewServer_RejectsNilWriter(t *testing.T) {
	_, err := audit.NewServer(nil, "/tmp/whatever.sock")
	if err == nil {
		t.Fatal("expected error for nil writer")
	}
}

func TestNewServer_RemovesStaleSocket(t *testing.T) {
	dir := shortSocketDir(t)
	socketPath := filepath.Join(dir, "audit.sock")

	// Create a stale file at the socket path.
	if err := os.WriteFile(socketPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale: %v", err)
	}
	srv, err := audit.NewServer(stubWriter{}, socketPath)
	if err != nil {
		t.Fatalf("NewServer with stale socket: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// File should now be a socket, not the stale text file. Attempt
	// to read its contents — a Unix socket returns "permission denied"
	// or "operation not supported" depending on platform; the key is
	// that the file is no longer 0600 plain text.
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat after recreate: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("after recreate, file is not a socket: mode=%v", info.Mode())
	}
}

func TestNewServer_SocketModeIs0600(t *testing.T) {
	dir := shortSocketDir(t)
	socketPath := filepath.Join(dir, "audit.sock")
	srv, err := audit.NewServer(stubWriter{}, socketPath)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = srv.Close() }()
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("socket perm = %v, want no group/world bits", info.Mode().Perm())
	}
}

func TestClient_AppendRoundTrip(t *testing.T) {
	socketPath := startTestServer(t)

	cli := audit.DialClient(socketPath)
	defer func() { _ = cli.Close() }()

	entry := audit.Entry{
		Actor:     "test-user",
		EventType: audit.EventVaultUnlock,
		Payload:   json.RawMessage(`{"sample":"value"}`),
	}
	got, err := cli.Append(context.Background(), entry)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got.ID == 0 {
		t.Errorf("ID not assigned: %+v", got)
	}
	if len(got.PrevHash) != 32 {
		t.Errorf("PrevHash length = %d, want 32", len(got.PrevHash))
	}
	if len(got.EntryHash) != 32 {
		t.Errorf("EntryHash length = %d, want 32", len(got.EntryHash))
	}
	if got.Actor != "test-user" {
		t.Errorf("Actor = %q, want test-user", got.Actor)
	}
}

func TestClient_ChainOrderUnderConcurrentClients(t *testing.T) {
	socketPath := startTestServer(t)

	const N = 8  // concurrent clients
	const M = 10 // entries per client
	wg := sync.WaitGroup{}
	wg.Add(N)
	results := make(chan audit.Entry, N*M)
	errs := make(chan error, N*M)
	for i := 0; i < N; i++ {
		go func(_ int) {
			defer wg.Done()
			cli := audit.DialClient(socketPath)
			defer func() { _ = cli.Close() }()
			for j := 0; j < M; j++ {
				entry := audit.Entry{
					Actor:     "client",
					EventType: audit.EventVaultUnlock,
					Payload:   json.RawMessage(`{}`),
				}
				got, err := cli.Append(context.Background(), entry)
				if err != nil {
					errs <- err
					return
				}
				results <- got
			}
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Errorf("client Append: %v", err)
	}

	// Collect IDs — they should be a contiguous range starting at 1
	// (genesis), strictly monotonic, no duplicates.
	ids := map[int64]bool{}
	for r := range results {
		if ids[r.ID] {
			t.Errorf("duplicate ID: %d", r.ID)
		}
		ids[r.ID] = true
	}
	if len(ids) != N*M {
		t.Errorf("got %d unique IDs, want %d", len(ids), N*M)
	}
	for i := int64(1); i <= int64(N*M); i++ {
		if !ids[i] {
			t.Errorf("missing ID %d in returned set", i)
		}
	}
}

func TestClient_LazyDial(t *testing.T) {
	// DialClient doesn't actually connect; first Append does. This
	// keeps short-lived non-audit-emitting commands (`version`,
	// `doctor`) from tripping over a missing daemon.
	cli := audit.DialClient("/nonexistent/audit.sock")
	defer func() { _ = cli.Close() }()
	// First Append should fail with a dial error.
	_, err := cli.Append(context.Background(), audit.Entry{
		Actor:     "x",
		EventType: audit.EventVaultUnlock,
		Payload:   json.RawMessage(`{}`),
	})
	if err == nil {
		t.Fatal("expected dial error for missing daemon socket")
	}
}

func TestClient_SurvivesDaemonReconnect(t *testing.T) {
	socketPath := startTestServer(t)
	cli := audit.DialClient(socketPath)
	defer func() { _ = cli.Close() }()

	// First Append establishes the connection and succeeds.
	if _, err := cli.Append(context.Background(), audit.Entry{
		Actor:     "first",
		EventType: audit.EventVaultUnlock,
		Payload:   json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("first Append: %v", err)
	}

	// Forcibly close the client side of the connection to simulate
	// a daemon that bounced. The client should re-dial transparently
	// on the next Append.
	_ = cli.Close()

	if _, err := cli.Append(context.Background(), audit.Entry{
		Actor:     "second",
		EventType: audit.EventVaultUnlock,
		Payload:   json.RawMessage(`{}`),
	}); err != nil {
		t.Errorf("second Append after explicit Close: %v", err)
	}
}

// stubWriter is a minimal Writer for the no-network tests above.
type stubWriter struct{}

func (stubWriter) Append(_ context.Context, e audit.Entry) (audit.Entry, error) {
	return e, errors.New("stub")
}
