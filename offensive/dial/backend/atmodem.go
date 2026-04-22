//go:build offensive

package backend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// ATModem drives a Hayes-compatible modem over any io.ReadWriter
// that speaks AT. The typical construction path from the CLI is:
//
//	rw, err := openSerial("/dev/ttyUSB0", 57600)   // caller
//	m := NewATModem(rw, "/dev/ttyUSB0", 45*time.Second)
//	defer m.Close()
//	res, err := m.Deliver(ctx, "+34911234567")
//
// The serial open is intentionally NOT inside this package —
// `tarm/serial` or `go.bug.st/serial` pulls a non-trivial
// dependency and the CLI already does device-open elsewhere.
// For tests we pass a net.Pipe() pair.
//
// Wire sequence per call (happy path):
//
//	→ ATZ<CR>                 (reset modem)
//	← OK
//	→ ATE0<CR>                (echo off)
//	← OK
//	→ ATDT<number>;<CR>       (tone dial, return-to-cmd-mode)
//	← CONNECT <baud>          → DispositionDelivered
//	  | NO ANSWER             → DispositionNoAnswer
//	  | BUSY                  → DispositionBusy
//	  | NO CARRIER / NO DIAL  → DispositionHangup
//	  | ERROR / timeout       → DispositionFailed
//	→ +++<800ms pause>ATH0<CR> (hang up)
//	← OK
//
// The `;` suffix on ATDT asks the modem to return to command
// mode on connect instead of switching to data mode. That way
// we can hang up cleanly without the `+++` escape race.
type ATModem struct {
	mu          sync.Mutex
	rw          io.ReadWriter
	br          *bufio.Reader // shared across read ops (see NewATModem)
	devicePath  string
	dialTimeout time.Duration
}

// NewATModem wraps rw (typically an open serial port) as an
// ATModem backend. `devicePath` is only used as a label in the
// returned Result.Raw line. `dialTimeout` caps the total time
// spent waiting for a result code after ATDT.
//
// A single bufio.Reader is cached on the struct so consecutive
// read operations (ATZ → OK, ATE0 → OK, ATDT → CONNECT) share
// the same buffer. Creating a fresh reader per call would
// discard any read-ahead bytes the previous call pulled but
// hadn't consumed — a classic serial-port bug that deadlocks
// the next read on a fully-drained underlying stream.
func NewATModem(rw io.ReadWriter, devicePath string, dialTimeout time.Duration) *ATModem {
	if dialTimeout <= 0 {
		dialTimeout = 45 * time.Second
	}
	return &ATModem{
		rw:          rw,
		br:          bufio.NewReader(rw),
		devicePath:  devicePath,
		dialTimeout: dialTimeout,
	}
}

// Name implements Backend.
func (m *ATModem) Name() string { return "atmodem" }

// Deliver implements Backend.
func (m *ATModem) Deliver(ctx context.Context, number string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	start := time.Now()
	if err := m.init(ctx); err != nil {
		return Result{
			Disposition: DispositionFailed,
			Reason:      fmt.Sprintf("init: %s", err),
			Duration:    time.Since(start),
		}, err
	}
	// Issue the dial.
	if err := m.writeAT("D" + "T" + number + ";"); err != nil {
		return Result{
			Disposition: DispositionFailed,
			Reason:      fmt.Sprintf("ATDT write: %s", err),
			Duration:    time.Since(start),
		}, err
	}
	// Await the terminal result.
	dialCtx, cancel := context.WithTimeout(ctx, m.dialTimeout)
	defer cancel()
	line, err := m.readUntilResult(dialCtx)
	res := Result{
		Raw:      line,
		Duration: time.Since(start),
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		res.Disposition = DispositionFailed
		res.Reason = "timeout"
	case err != nil:
		res.Disposition = DispositionFailed
		res.Reason = err.Error()
	default:
		res.Disposition, res.Reason = classifyATResult(line)
	}
	// Always try to hang up cleanly. Ignore errors — we've
	// already classified the outcome.
	m.hangup()
	return res, nil
}

// Close implements Backend. Issues ATH0 best-effort; does NOT
// close the underlying io.ReadWriter (the caller opened it and
// owns its lifetime).
func (m *ATModem) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hangup()
	return nil
}

// init runs ATZ + ATE0 so echo is off and the modem is in a
// known state.
func (m *ATModem) init(ctx context.Context) error {
	if err := m.writeAT("Z"); err != nil {
		return err
	}
	if err := m.readOKContext(ctx, 2*time.Second); err != nil {
		return fmt.Errorf("ATZ: %w", err)
	}
	if err := m.writeAT("E0"); err != nil {
		return err
	}
	if err := m.readOKContext(ctx, 500*time.Millisecond); err != nil {
		return fmt.Errorf("ATE0: %w", err)
	}
	return nil
}

// atResultERROR is the Hayes final result code for an errored
// command. Named so gosimplicity / goconst stays happy.
const atResultERROR = "ERROR"

// writeAT prepends "AT" + writes + terminates with CR.
func (m *ATModem) writeAT(cmd string) error {
	_, err := m.rw.Write([]byte("AT" + cmd + "\r"))
	return err
}

// hangup emits ATH0 best-effort. Deliberately returns no error
// — even if the underlying write fails the call is over, the
// modem's own inactivity timer will drop the line. Callers
// who want to surface write errors should call writeAT("H0")
// directly.
func (m *ATModem) hangup() {
	// Escape sequence — modems expect ~1s silence before +++.
	// We can't sleep that long in every Close, so send ATH0
	// directly; if we were still in command mode (we set ";"
	// on ATDT) this works. If in data mode the call is already
	// lost by now.
	_ = m.writeAT("H0")
}

// readUntilResult reads one line at a time from the shared
// bufio.Reader until a terminal AT result code appears
// (CONNECT / NO ANSWER / BUSY / NO CARRIER / NO DIAL TONE /
// ERROR / OK). Returns the matched line.
//
// The raw bufio.ReadString is not context-aware (it blocks on
// the underlying conn's Read indefinitely) so we run the read
// in a goroutine and race it against ctx.Done(). That makes the
// context deadline authoritative — an unresponsive modem will
// hit the dialTimeout and the caller sees a typed error.
func (m *ATModem) readUntilResult(ctx context.Context) (string, error) {
	type lineOrErr struct {
		line string
		err  error
	}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		ch := make(chan lineOrErr, 1)
		go func() {
			line, err := m.br.ReadString('\n')
			ch <- lineOrErr{line: strings.TrimRight(line, "\r\n "), err: err}
		}()
		var res lineOrErr
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case res = <-ch:
		}
		if res.err != nil && res.line == "" {
			return "", res.err
		}
		if res.line == "" {
			continue
		}
		if isATTerminalResult(res.line) {
			return res.line, nil
		}
	}
}

// readOKContext waits for an "OK" line within `within` or
// ctx.Deadline, whichever is earlier. Reads from the shared
// bufio.Reader so bytes don't get lost between calls.
func (m *ATModem) readOKContext(ctx context.Context, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		line, err := m.br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n ")
		if err != nil && line == "" {
			return err
		}
		if line == "" {
			continue
		}
		if line == "OK" {
			return nil
		}
		if line == atResultERROR {
			return errors.New("modem ERROR")
		}
	}
}

// isATTerminalResult returns true when `line` is one of the
// standard Hayes final result codes.
func isATTerminalResult(line string) bool {
	switch {
	case strings.HasPrefix(line, "CONNECT"),
		line == "NO ANSWER",
		line == "NO CARRIER",
		line == "NO DIAL TONE",
		line == "BUSY",
		line == atResultERROR,
		line == "OK":
		return true
	}
	return false
}

// classifyATResult maps a terminal Hayes code to a Disposition
// + human-readable Reason.
func classifyATResult(line string) (Disposition, string) {
	switch {
	case strings.HasPrefix(line, "CONNECT"):
		return DispositionDelivered, line
	case line == "NO ANSWER":
		return DispositionNoAnswer, "no answer"
	case line == "BUSY":
		return DispositionBusy, "busy"
	case line == "NO CARRIER", line == "NO DIAL TONE":
		return DispositionHangup, strings.ToLower(line)
	case line == atResultERROR:
		return DispositionFailed, "modem ERROR"
	case line == "OK":
		// Rare: modem reported OK without a preceding CONNECT.
		// Treat as hangup — nothing connected.
		return DispositionHangup, "OK without CONNECT"
	}
	return DispositionFailed, fmt.Sprintf("unknown result: %s", line)
}
