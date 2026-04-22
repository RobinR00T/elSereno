//go:build offensive

package fox

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"

	"local/elsereno/offensive/confirm"
)

// WriteGatedHandler enforces Niagara Fox command gating on a
// line-oriented connection. Fox commands are ASCII lines of the
// form `fox <verb> <args...>\n`, for example:
//
//	fox a 0 -1 fox hello\n
//	fox session begin\n
//	fox auth login operator\n
//	fox property set {slot:/Drivers:foo} 42\n     ← mutating
//
// Verbs in the allowlist are forwarded; everything else gets a
// Fox-native refusal: `fox a 0 -1 fox denied\n`.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedCommand
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	authorised bool
}

// DefaultReadVerbs is the list of Fox verbs that are always
// considered read-only and pass regardless of the allowlist.
var DefaultReadVerbs = map[string]bool{
	"hello": true,
	"a":     true, // "fox a" is the banner / low-level ack prefix
	"get":   true,
	"list":  true,
}

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
var ErrSessionNotAuthorised = errors.New("fox: write-gated proxy requires Authorise() first")

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

func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	r := bufio.NewReader(client)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return err
		}
		if h.shouldForward(line) {
			if _, err := upstream.Write(line); err != nil {
				return err
			}
			continue
		}
		if _, err := clientWriter.Write([]byte("fox a 0 -1 fox denied\n")); err != nil {
			return err
		}
	}
}

// shouldForward extracts the verb from the line and consults the
// allowlist. Lines that don't start with "fox " are forwarded
// unchanged (could be the client's raw handshake).
func (h *WriteGatedHandler) shouldForward(line []byte) bool {
	s := strings.TrimSpace(string(line))
	if !strings.HasPrefix(s, "fox ") {
		return true
	}
	tail := strings.TrimPrefix(s, "fox ")
	// First token after "fox " is the verb.
	verb := firstToken(tail)
	if verb == "" {
		return true
	}
	if DefaultReadVerbs[verb] {
		return true
	}
	for _, a := range h.Allowed {
		if a.Verb == verb {
			return true
		}
	}
	return false
}

// firstToken returns the first whitespace-delimited token.
func firstToken(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\t' {
			return s[:i]
		}
	}
	return s
}
