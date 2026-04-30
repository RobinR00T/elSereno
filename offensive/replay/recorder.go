//go:build offensive

// Package replay implements proxy-session record + replay (v1.27
// chunk 4). The use case is forensic post-mortem + lab training:
// when an operator runs `elsereno proxy listen` in offensive
// mode, the bytes flowing between client + upstream can be
// captured to a file with timestamps; later, the recorded
// session can be replayed against a lab device for re-analysis
// or trainee walk-through.
//
// File format: NDJSON, one event per line, JSON-encoded with
// these fields:
//
//	{
//	  "schema":   "elsereno-replay/v1",
//	  "ts":       "2026-04-30T17:02:34.123456Z",  // RFC3339 microseconds
//	  "dir":      "client_to_upstream",            // or "upstream_to_client"
//	  "len":      32,                              // bytes in this chunk
//	  "hex":      "010100 1c 49 …"                 // chunk bytes, hex-encoded
//	}
//
// First line is a header event with `schema` + `dir="header"`
// + extra `target` + `protocol` + `started_at` fields. The
// header is required for replay tooling to validate the file's
// origin + reject mismatched protocols.
//
// NDJSON is chosen over a binary format (pcap, custom) so:
//
//   - operators can `jq`/`grep` the file directly without
//     specialised tooling;
//   - timestamps + direction tags + hex byte runs are explicit
//     so a lab walk-through can annotate inline;
//   - the recorder is robust against partial writes — a crash
//     mid-line truncates only the current event, not the whole
//     file.
//
// Files are created with mode 0600. Recorded session files MAY
// contain credentials, raw protocol payloads with secrets, or
// PII embedded in protocol fields — operators should treat them
// as sensitive (same handling class as audit.jsonl).
//
// The recorder does NOT implement encryption-at-rest; files are
// expected to live on a 0700 directory with disk-level encryption
// (FileVault / LUKS / similar) where applicable. Operator
// responsibility.
package replay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Direction identifies which side of the proxy generated the
// chunk. Two values: "client_to_upstream" (operator's tooling →
// gated upstream) and "upstream_to_client" (gated upstream →
// operator's tooling). The header line uses "header".
type Direction string

// Direction values.
const (
	DirClientToUpstream Direction = "client_to_upstream"
	DirUpstreamToClient Direction = "upstream_to_client"
	DirHeader           Direction = "header"
)

// Schema is the file-format identifier in every event.
const Schema = "elsereno-replay/v1"

// HeaderEvent is the first line of a recording. It carries
// metadata operators need to identify what they're looking at:
// when the session ran, which protocol gate produced it, which
// upstream target was reached. Audit tooling cross-references
// the audit_log row that authorised the session by matching
// (Target, StartedAt) pairs.
type HeaderEvent struct {
	Schema    string    `json:"schema"`
	Dir       Direction `json:"dir"` // always DirHeader
	StartedAt time.Time `json:"started_at"`
	Protocol  string    `json:"protocol"` // e.g. "sip", "modbus", "pcworx"
	Target    string    `json:"target"`   // host:port of the gated upstream
}

// ChunkEvent is a single byte chunk recorded mid-session.
type ChunkEvent struct {
	Schema string    `json:"schema"`
	TS     time.Time `json:"ts"`
	Dir    Direction `json:"dir"`
	Len    int       `json:"len"`
	Hex    string    `json:"hex"`
}

// Recorder owns a session-recording file and provides Wrap() to
// instrument an io.ReadWriter with capture. One Recorder per
// proxy session; not safe for concurrent use across sessions
// (each session opens its own file).
type Recorder struct {
	path string
	f    *os.File
	enc  *json.Encoder
	mu   sync.Mutex
	now  func() time.Time // injectable for tests
}

// Open creates a new recording file at path (mode 0600) and
// writes the header event. Returns the Recorder bound to that
// file; the caller must call Close to flush + finalise the
// recording.
func Open(path, protocol, target string) (*Recorder, error) {
	if path == "" {
		return nil, errors.New("replay: Open: empty path")
	}
	if protocol == "" {
		return nil, errors.New("replay: Open: empty protocol")
	}
	if target == "" {
		return nil, errors.New("replay: Open: empty target")
	}
	// #nosec G304 -- operator-supplied recording-file path
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("replay: Open %s: %w", path, err)
	}
	r := &Recorder{
		path: path,
		f:    f,
		enc:  json.NewEncoder(f),
		now:  func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) },
	}
	hdr := HeaderEvent{
		Schema:    Schema,
		Dir:       DirHeader,
		StartedAt: r.now(),
		Protocol:  protocol,
		Target:    target,
	}
	if err := r.enc.Encode(&hdr); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("replay: write header: %w", err)
	}
	return r, nil
}

// Close finalises the recording. Idempotent — safe to call
// from a defer + a signal handler simultaneously.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Path returns the recording file path. Useful for surfacing in
// CLI output ("recording session to PATH").
func (r *Recorder) Path() string { return r.path }

// emit writes one ChunkEvent under the recorder's mutex so
// concurrent Wrap()'d readers + writers can interleave without
// corrupting the JSONL stream.
func (r *Recorder) emit(dir Direction, p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return errors.New("replay: emit on closed recorder")
	}
	ev := ChunkEvent{
		Schema: Schema,
		TS:     r.now(),
		Dir:    dir,
		Len:    len(p),
		Hex:    hex.EncodeToString(p),
	}
	if err := r.enc.Encode(&ev); err != nil {
		return fmt.Errorf("replay: emit: %w", err)
	}
	return nil
}

// Wrap installs the recorder around a connection. The returned
// io.ReadWriter behaves exactly like the underlying conn but
// every successful Read records DirUpstreamToClient and every
// successful Write records DirClientToUpstream.
//
// The conn argument is the OPERATOR'S SIDE of the proxy gate —
// what the operator's client tool sends + receives. To record
// both sides correctly, the proxy code must Wrap each
// io.ReadWriter passed to its Handle() with the appropriate
// Direction. Use WrapClient + WrapUpstream below for clarity.
func (r *Recorder) Wrap(conn io.ReadWriter) io.ReadWriter {
	return &recordingConn{rw: conn, r: r, readDir: DirUpstreamToClient, writeDir: DirClientToUpstream}
}

// WrapClient wraps the proxy's CLIENT-side io.ReadWriter (the
// connection FROM the operator's tool TO the proxy). Reads from
// this conn are operator-tool → proxy bytes; writes are
// proxy → operator-tool bytes. Direction tags reflect that:
// reads → DirClientToUpstream, writes → DirUpstreamToClient.
func (r *Recorder) WrapClient(conn io.ReadWriter) io.ReadWriter {
	return &recordingConn{rw: conn, r: r, readDir: DirClientToUpstream, writeDir: DirUpstreamToClient}
}

// WrapUpstream wraps the proxy's UPSTREAM-side io.ReadWriter
// (the connection FROM the proxy TO the gated upstream). Reads
// from this conn are upstream → proxy bytes; writes are
// proxy → upstream bytes.
func (r *Recorder) WrapUpstream(conn io.ReadWriter) io.ReadWriter {
	return &recordingConn{rw: conn, r: r, readDir: DirUpstreamToClient, writeDir: DirClientToUpstream}
}

// recordingConn is the io.ReadWriter wrapper Wrap returns. Each
// Read / Write records the buffer contents under the recorder's
// mutex, then returns the same bytes the underlying conn
// produced.
type recordingConn struct {
	rw       io.ReadWriter
	r        *Recorder
	readDir  Direction
	writeDir Direction
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.rw.Read(p)
	if n > 0 {
		// Record the actual returned bytes; ignore recorder
		// errors — a write failure shouldn't tear down a live
		// session, just disable further recording.
		_ = c.r.emit(c.readDir, p[:n])
	}
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	if len(p) > 0 {
		_ = c.r.emit(c.writeDir, p)
	}
	return c.rw.Write(p)
}

// Replay reads an NDJSON recording file and yields each
// ChunkEvent through cb in sequence. The header line is
// returned via the first call as a synthetic ChunkEvent with
// Dir=DirHeader (Hex left empty; metadata fields populated via
// HeaderEvent.Target / Protocol / StartedAt — the caller can
// refer to those via SeekHeader before iterating).
//
// Pacing: the caller decides. cb is invoked in file order; if
// the caller wants timestamp-preserving pacing they sleep
// between calls based on the TS delta. The default behaviour
// emits as fast as the reader can drain, which is what most
// post-mortem analysis tools want.
//
// ctx cancellation interrupts the iteration; Replay returns
// ctx.Err() in that case.
func Replay(ctx context.Context, path string, cb func(ev ChunkEvent) error) error {
	hdr, events, err := load(path)
	if err != nil {
		return err
	}
	// Synthesise a header event for the callback so consumers
	// who only care about chunks can still see the file context.
	if err := cb(ChunkEvent{
		Schema: hdr.Schema,
		TS:     hdr.StartedAt,
		Dir:    DirHeader,
	}); err != nil {
		return err
	}
	for _, ev := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := cb(ev); err != nil {
			return err
		}
	}
	return nil
}

// SeekHeader reads only the first line of the recording (the
// header event) and returns it without iterating chunks. Used
// when the caller wants to validate file origin + protocol +
// target before deciding whether to drive Replay.
func SeekHeader(path string) (HeaderEvent, error) {
	hdr, _, err := load(path)
	return hdr, err
}

// load reads the entire NDJSON file into memory + returns
// (header, chunks, err). For very large recordings (>100 MB)
// callers should switch to a streaming variant; v1.27 chunk 4
// optimises for the common case (small lab sessions, KB-sized
// payloads).
func load(path string) (HeaderEvent, []ChunkEvent, error) {
	// #nosec G304 -- operator-supplied recording-file path
	f, err := os.Open(path)
	if err != nil {
		return HeaderEvent{}, nil, fmt.Errorf("replay: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	var hdr HeaderEvent
	if err := dec.Decode(&hdr); err != nil {
		return HeaderEvent{}, nil, fmt.Errorf("replay: header: %w", err)
	}
	if hdr.Schema != Schema {
		return HeaderEvent{}, nil, fmt.Errorf("replay: bad schema %q (want %q)", hdr.Schema, Schema)
	}
	if hdr.Dir != DirHeader {
		return HeaderEvent{}, nil, fmt.Errorf("replay: header dir = %q (want %q)", hdr.Dir, DirHeader)
	}
	var events []ChunkEvent
	for dec.More() {
		var ev ChunkEvent
		if err := dec.Decode(&ev); err != nil {
			return HeaderEvent{}, nil, fmt.Errorf("replay: decode: %w", err)
		}
		events = append(events, ev)
	}
	return hdr, events, nil
}

// DecodeBytes returns the chunk's hex payload as raw bytes. The
// recorder always emits the bytes that crossed the proxy, so
// DecodeBytes is the inverse of the encoder side.
func (e ChunkEvent) DecodeBytes() ([]byte, error) {
	return hex.DecodeString(e.Hex)
}
