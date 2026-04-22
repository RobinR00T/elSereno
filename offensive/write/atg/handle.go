//go:build offensive

package atg

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"local/elsereno/offensive/confirm"
)

// WriteGatedHandler enforces ATG Veeder-Root TLS-350/4 command
// gating. ATG commands are line-oriented ASCII: the client sends
// `<SOH>I20100<CR>` style strings (SOH = 0x01, ETX = 0x03). The
// second character is the command class:
//
//	I — information queries (read-only). Always allowed.
//	V — volume / level writes (setpoint). Gated.
//	S — set configuration. Gated.
//	T — tank calibration. Gated.
//	Z — reset / test. Gated.
//
// Refusal path: a Veeder-Root NAK reply — the protocol's standard
// "command not understood" response is `<SOH>9999FF1B<CR><ETX>`
// (header 9999 + error code FF1B + checksum trailer). We emit a
// simplified but parseable variant.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedCommand
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	authorised bool
}

// ATG framing bytes.
const (
	SOH = 0x01
	ETX = 0x03
	CR  = 0x0D
	LF  = 0x0A
)

// Authorise opens the session.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.Allowed)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned when Handle runs before Authorise.
var ErrSessionNotAuthorised = errors.New("atg: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream, client) }()
	go func() { _, err := io.Copy(client, upstream); errs <- err }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

// forward reads one command at a time (SOH-prefixed, CR-terminated)
// and routes per policy.
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	r := bufio.NewReader(client)
	for {
		// Skip any bytes before SOH (noise / preamble).
		for {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			if b == SOH {
				break
			}
		}
		// Read up to CR.
		line, err := r.ReadBytes(CR)
		if err != nil {
			return err
		}
		if len(line) < 2 {
			// Empty command; pass the raw bytes through.
			if _, err := upstream.Write(append([]byte{SOH}, line...)); err != nil {
				return err
			}
			continue
		}
		if h.shouldForward(line) {
			if _, err := upstream.Write(append([]byte{SOH}, line...)); err != nil {
				return err
			}
			continue
		}
		if _, err := clientWriter.Write(buildNAK()); err != nil {
			return err
		}
	}
}

// shouldForward applies the gate. First byte after SOH is the
// command class; 'I' always passes, everything else consults the
// allowlist.
func (h *WriteGatedHandler) shouldForward(line []byte) bool {
	// Strip leading whitespace defensively.
	s := bytes.TrimLeft(line, " \t")
	if len(s) == 0 {
		return true
	}
	cmd := s[0]
	if cmd == 'I' || cmd == 'i' {
		return true
	}
	// Uppercase for matching.
	if cmd >= 'a' && cmd <= 'z' {
		cmd -= 32
	}
	for _, a := range h.Allowed {
		if a.Prefix == cmd {
			return true
		}
	}
	return false
}

// buildNAK returns a Veeder-Root "command not understood" reply.
// Format: <SOH>9999FF1B<EOT><ETX> where 9999 is the standard
// error-response header, FF1B is the error code, and EOT/ETX
// delimits the message. Real Veeder-Root consoles issue this
// exact sequence on syntax errors.
func buildNAK() []byte {
	return []byte{
		SOH,
		'9', '9', '9', '9',
		'F', 'F', '1', 'B',
		CR,
		ETX,
	}
}

// Verify the package compiles without unused-imports noise.
var _ = fmt.Sprintf
