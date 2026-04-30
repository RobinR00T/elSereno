//go:build offensive

// Package mms implements the offensive write-gate proxy for
// IEC 61850 Manufacturing Message Specification (MMS) on TCP/102.
//
// MMS is the application-layer protocol every IEC 61850-8-1
// substation device speaks: protection relays, RTUs, merging
// units, station controllers. The default-build fingerprint
// plugin (`internal/protocols/mms`) ships a fail-closed proxy
// because the wire layer beyond the COTP Connect-Confirm is the
// OSI session layer + ACSE association + MMS PDUs (ASN.1 BER) —
// a substantial parser surface. This offensive variant replaces
// that fail-closed handler when `-tags offensive` is built AND
// the three operator fences pass (--accept-writes +
// --confirm-target + --confirm-token).
//
// **Important honest scope note**: unlike the v1.4 SIP / IAX2 /
// Modbus / OPC UA / BACnet gates that parse the request layer
// and apply method-level / function-code-level allowlists, the
// MMS gate is **session-level**. After Authorise succeeds, the
// handler relays bytes verbatim between client and upstream. The
// operator's Authorise call is the entire gate.
//
// Why session-level rather than wire-level: a true MMS write-
// gate would need an ASN.1 BER parser walking the OSI session
// SPDU + ACSE A-ASSOCIATE + MMS PDUs (ConfirmedRequestPDU /
// Read / Write / Status / Identify / etc.) to extract the
// Object reference + service code. That's a significant parser
// surface (think v1.6 OPC UA per-NodeId × 10) and shipping it
// without test vectors against a real substation device risks
// gates that misclassify operator traffic (false positives that
// block legitimate reads, or — worse — false negatives that pass
// writes through). v1.27 chunk 3 therefore ships the triple-
// confirm fence + audit row + byte relay; full ASN.1-walking
// MMS PDU gating is the v1.35 candidate (MMS ACSE association
// layer in TODO-vNext.md).
//
// What you still get from this chunk:
//   - The triple-confirm fence (build tag + --accept-writes +
//     --confirm-target + --confirm-token) protects the upstream.
//     A misconfigured operator command can't accidentally relay
//     MMS bytes — Authorise must succeed first.
//   - The audit chain records the session (offensive_allowed
//     event with proxy_session operation + target hash) so the
//     forensic record exists even though the gate doesn't slice
//     individual commands.
//   - The session-level allowlist hash incorporates the operator's
//     declared "intent string" so two distinct sessions with
//     different operational rationale produce different
//     confirm-tokens. (See AllowedIntent below.)
package mms

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
// for "setpoint update on production line A".
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
		Protocol:    "mms",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// mms fail-closed proxy. After Authorise succeeds, Handle
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
	// recorder. Nil disables recording — the gate behaves exactly
	// as it did pre-v1.28.
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
		return errors.New("mms: Authorise: at least one AllowedIntent.Description is required")
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
var ErrSessionNotAuthorised = errors.New("mms: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler. After Authorise has
// succeeded, splits into two io.Copy goroutines (client →
// upstream + upstream → client) and waits for either side to
// close. Bytes are relayed verbatim — no per-frame parsing or
// allowlist gating in v1.27 chunk 3.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
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
// for `elsereno proxy listen` to print "operating in mms
// session-level mode" so operators see the granularity choice
// up-front rather than after running into a surprise.
func (h *WriteGatedHandler) Description() string {
	return fmt.Sprintf("mms session-level proxy (target=%s, intents=%d) — bytes relayed verbatim once Authorise succeeds", h.Target, len(h.Allowed))
}
