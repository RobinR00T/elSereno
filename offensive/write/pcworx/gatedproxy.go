//go:build offensive

// Package pcworx implements the offensive write-gate proxy for
// the Phoenix Contact PCWorx runtime protocol (TCP/1962).
//
// PCWorx is the proprietary binary protocol used by ILC PLCs +
// AXC F + RFC PN PLCs. The default-build fingerprint plugin
// (`internal/protocols/pcworx`) ships a fail-closed proxy
// because the wire layer beyond the 32-byte IBETH01 hello is
// poorly documented publicly. This offensive variant replaces
// that fail-closed handler when `-tags offensive` is built AND
// the three operator fences pass (--accept-writes +
// --confirm-target + --confirm-token).
//
// **Important honest scope note**: unlike the v1.4 SIP / IAX2 /
// Modbus / OPC UA / BACnet gates that parse the request layer
// and apply method-level / function-code-level allowlists, the
// PCWorx gate is **session-level**. After Authorise succeeds, the
// handler relays bytes verbatim between client and upstream. The
// operator's Authorise call is the entire gate.
//
// Why session-level rather than wire-level: the PCWorx command
// vocabulary post-hello (variable read / write / runtime control
// IDs) is not authoritatively documented in any public reference
// I could validate. Inventing a wire-parser based on conflicting
// nmap-NSE / Metasploit / ICS-CERT-advisory excerpts would risk
// shipping a gate that incorrectly classifies operator traffic
// (false positives that block legitimate reads, or — worse —
// false negatives that pass writes through). The v1.27 chunk 2
// scope is therefore deliberate: ship the triple-confirm fence
// + audit row + relay, leave wire-level command gating to a
// future cycle once test vectors against real ILC firmware are
// available.
//
// What you still get from this chunk:
//   - The triple-confirm fence (build tag + --accept-writes +
//     --confirm-target + --confirm-token) protects the upstream.
//     A misconfigured operator command can't accidentally relay
//     PCWorx bytes — Authorise must succeed first.
//   - The audit chain records the session (offensive_allowed
//     event with proxy_session operation + target hash) so the
//     forensic record exists even though the gate doesn't slice
//     individual commands.
//   - The session-level allowlist hash incorporates the operator's
//     declared "intent string" so two distinct sessions with
//     different operational rationale produce different
//     confirm-tokens. (See AllowedIntent below.)
package pcworx

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedIntent is the operator's free-text rationale for the
// session. It does NOT gate any wire-level behaviour — it's
// recorded in the session PayloadHash so two sessions with
// different rationale produce different confirm-tokens. Useful
// for audit lineage: a token minted for "ILC reset to factory
// before commissioning" is structurally distinct from one minted
// for "live config update on production line A".
type AllowedIntent struct {
	// Description is a short operator-supplied tag. Required;
	// empty string makes the dry-run + Authorise reject.
	Description string
}

// AllowlistHash returns the deterministic SHA-256 of the
// session intent + target. Sorted by description (case-folded)
// so operator typing variations don't produce different tokens.
func AllowlistHash(target string, allowed []AllowedIntent) [32]byte {
	keys := make([]string, 0, len(allowed))
	for _, a := range allowed {
		k := strings.ToLower(strings.TrimSpace(a.Description))
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0x00})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation for the session.
// Same shape as the modbus / opcua / sip templates so the CLI
// wiring stays uniform.
func SessionMutation(target string, allowed []AllowedIntent) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "pcworx",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// pcworx fail-closed proxy. After Authorise succeeds, Handle
// relays bytes verbatim between client and upstream.
//
// Triple-confirm contract:
//   - Caller must populate Target / Allowed / Deriver / Auditor /
//     SessionConfirm before invoking Authorise().
//   - Allowed must contain at least one non-empty AllowedIntent
//     so the operator's rationale is captured + audited.
//   - Authorise() returns error if any fence fails; Handle()
//     refuses to run until Authorise() succeeds.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedIntent
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	// Recorder is the optional v1.28-chunk-3 hook for capturing
	// the proxy session to an NDJSON file. When non-nil, Handle
	// wraps both client + upstream io.ReadWriter through the
	// recorder so every byte that crosses the gate is timestamped
	// + direction-tagged + persisted. Nil disables recording —
	// the gate behaves exactly as it did pre-v1.28.
	//
	// The operator's CLI wrapper is responsible for opening +
	// closing the Recorder; the gate doesn't manage its lifetime.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	// Reject sessions with no operator-supplied rationale — the
	// audit lineage requires at least one non-empty intent so
	// future forensic queries can join "what was this session
	// for?" against the operator's declared purpose.
	any := false
	for _, a := range h.Allowed {
		if strings.TrimSpace(a.Description) != "" {
			any = true
			break
		}
	}
	if !any {
		return errors.New("pcworx: Authorise: at least one AllowedIntent.Description is required")
	}
	m := SessionMutation(h.Target, h.Allowed)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("pcworx: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler. After Authorise has
// succeeded, splits into two io.Copy goroutines (client →
// upstream + upstream → client) and waits for either side to
// close. Bytes are relayed verbatim — no per-frame parsing or
// allowlist gating in v1.27 chunk 2.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	// v1.28 chunk 3: optional record-replay capture. Wrap both
	// io.ReadWriter pairs through the recorder when one is
	// configured; bytes flow through transparently while being
	// timestamped + direction-tagged into the NDJSON file.
	if h.Recorder != nil {
		client = h.Recorder.WrapClient(client)
		upstream = h.Recorder.WrapUpstream(upstream)
	}
	errs := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, client)
		errs <- err
	}()
	go func() {
		_, err := io.Copy(client, upstream)
		errs <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

// Description returns a one-line summary of the proxy's
// operational scope, for surfacing in CLI status output. Useful
// for `elsereno proxy listen` to print "operating in pcworx
// session-level mode" so operators see the granularity choice
// up-front rather than after running into a surprise.
func (h *WriteGatedHandler) Description() string {
	return fmt.Sprintf("pcworx session-level proxy (target=%s, intents=%d) — bytes relayed verbatim once Authorise succeeds", h.Target, len(h.Allowed))
}
