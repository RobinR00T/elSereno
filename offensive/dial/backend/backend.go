//go:build offensive

// Package backend defines the pluggable interface every dial
// delivery backend (modem / VoIP / mock) must satisfy, plus the
// shared result shape used by the batch CLI.
//
// v1.2 ships three concrete implementations:
//
//   - `mock`: records intent + returns a canned disposition.
//     Default; no hardware touched. Safe for CI + dry-runs.
//   - `atmodem`: drives a Hayes-compatible modem over a serial
//     device (typically `/dev/ttyUSB0`). Uses the same
//     AT framing as `internal/protocols/atmodem` for
//     consistency with the read-only probe path.
//   - `voip-sip`: SIP INVITE + BYE over UDP/TCP against a SIP
//     proxy. No RTP is sent — the "dial" completes on
//     200 OK + ACK and is cancelled with BYE immediately.
//
// The offensive dial CLI (`elsereno dial batch`) selects a
// backend via `--backend`; the default remains `mock` (preview)
// so an operator who forgets to choose doesn't accidentally
// drive a real phone line.
//
// Every backend MUST install the seccomp `dial` profile before
// opening any fd — the CLI does that before calling Deliver.
// Backends that need network sockets (voip-sip) must run in a
// separate process because the seccomp dial profile blocks
// socket() on the Elsereno parent. v1.2 ships the interface +
// the mock + atmodem; the voip-sip subprocess implementation
// ships as a distinct `elsereno-dial-voip-sip` binary because
// of the sandbox split.
package backend

import (
	"context"
	"time"
)

// Disposition is the terminal state of a single Deliver call.
// The set is deliberately small so operators can triage a
// batch by disposition without reading free-text reasons.
type Disposition string

// Terminal dispositions a Deliver may return.
const (
	// DispositionPreview: no hardware action taken. Used by the
	// mock backend when `--disposition preview` is passed.
	DispositionPreview Disposition = "preview"
	// DispositionDelivered: the backend reports the call reached
	// the PSTN / SIP endpoint (modem CONNECT or SIP 200 OK).
	DispositionDelivered Disposition = "delivered"
	// DispositionNoAnswer: the backend waited the timeout and
	// got no pickup (modem NO ANSWER / SIP 486 / 487 / 480).
	DispositionNoAnswer Disposition = "no-answer"
	// DispositionBusy: remote indicated busy (modem BUSY / SIP 486).
	DispositionBusy Disposition = "busy"
	// DispositionHangup: far side hung up before we expected
	// (modem NO CARRIER mid-call / SIP BYE from remote).
	DispositionHangup Disposition = "hangup"
	// DispositionFailed: the backend errored before reaching the
	// endpoint (serial I/O error, SIP 5xx, DNS failure).
	DispositionFailed Disposition = "failed"
)

// Result is returned by every Deliver call regardless of
// disposition. `Raw` is the backend-native response line (modem
// result code or SIP response line) so audit consumers can
// reconstruct the low-level interaction.
type Result struct {
	// Disposition is the terminal outcome classification.
	Disposition Disposition
	// Raw is the backend-specific response. Truncated to 512
	// bytes by the dialer, and render.SafeBytes-sanitised by
	// the CLI before audit serialisation.
	Raw string
	// Reason is a short human-readable detail (e.g. "CONNECT
	// 57600" or "SIP/2.0 486 Busy Here").
	Reason string
	// Duration is the wall-clock elapsed from Deliver call
	// start to terminal disposition.
	Duration time.Duration
}

// Backend is the interface every dial implementation satisfies.
// Deliver is called once per number AFTER the dial guard has
// already approved it; the backend MUST NOT re-check the ≤3-
// digit rule or scope (those are CLI invariants).
//
// Context semantics:
//   - ctx.Deadline is honoured: a Deliver that doesn't complete
//     by then MUST return DispositionFailed with Reason = "timeout".
//   - ctx.Err on cancel MUST trigger DispositionFailed +
//     Reason = "cancelled" + release of any underlying fd.
type Backend interface {
	// Name returns a short identifier ("mock" / "atmodem" /
	// "voip-sip") used in logs + audit payloads.
	Name() string
	// Deliver attempts to dial `normalisedNumber` (digits only,
	// same shape as `dial.Normalise` output). Returns a Result
	// whose Disposition is always set — no nil Result on any
	// error path.
	Deliver(ctx context.Context, normalisedNumber string) (Result, error)
	// Close releases any persistent resources (open serial fd,
	// cached SIP registration). Safe to call multiple times.
	Close() error
}
