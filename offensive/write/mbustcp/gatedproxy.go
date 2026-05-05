//go:build offensive

// Package mbustcp implements the offensive write-gate proxy for
// M-Bus over TCP on (typically) TCP/10001. M-Bus is the European
// metering protocol (EN 13757-3 + EN 13757-4) covering electricity,
// gas, water, heat, and heat-cost-allocator meters. Writing to a
// meter via SND_UD can: re-tariff, reset accumulators, reassign
// the primary address, change the link baudrate, push firmware,
// or trigger a sync action across a meter group.
//
// Architecture follows the established WriteGatedHandler template
// (mirrors offensive/write/modbus + offensive/write/iax2): per-
// session Authorise on the SHA-256 of a sorted allowlist, per-
// frame filtering at wire-parse time, no per-frame token.
//
// Two-tier gate (control field + per-(CI, address) tuple):
//
//  1. **Control field level** — only SND_UD (0x53/0x73) is
//     mutating. All other controls (SND_NKE, REQ_UD1, REQ_UD2,
//     ACK, RSP_UD) pass without an allowlist entry.
//
//  2. **Per-(CI, address) level** — within SND_UD, refuse any
//     frame whose (CI, address) tuple isn't in the allowlist.
//     Wildcards: CI=0 matches any CI; Address=0 matches any
//     address. The operator picks granularity:
//     - {CI: CIDataSend, Address: 0x05} — Data Send only,
//     only to meter 5
//     - {CI: 0, Address: 0x05} — any CI, only to meter 5
//     - {CI: CIDataSend, Address: 0} — Data Send only, any
//     meter (NOT recommended; meters share a primary address
//     on shared M-Bus links).
//
// Refusal mode: silent drop. M-Bus has no "permission denied"
// frame; the cleanest refusal is to drop the frame and let the
// client time out. Any well-behaved master retransmits a couple
// of times then surfaces a timeout error.
//
// Out of scope (slated future):
//
//   - **Per-CI argument parsing** — set-baudrate (CI 0x56..0x5D)
//     leaks the baudrate in the CI byte itself, but Data Send
//     (0x51) carries the parameter ID + value in the UD payload.
//     Per-DIB parsing for fine-grained "allow setting tariff but
//     not primary address" is not in this chunk.
//   - **Secondary-addressing flow** — CI 0x52 (Select Slave) +
//     subsequent SND_UD pair. Currently each frame is gated
//     independently; a future cycle could track the "currently
//     selected slave" and apply gating per-slave.
//   - **CLI flag plumbing** in cmd_write_offensive.go — same
//     pattern as v1.52/v1.53/v1.55.
package mbustcp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	mbwire "local/elsereno/internal/protocols/mbustcp/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedSNDUD scopes a single (CI, primary-address) tuple the
// operator has authorised inside the SND_UD command. Wildcards:
// CI=0 matches any CI; Address=0 matches any address. The empty
// AllowedSNDUD{} is treated as "match nothing" (NOT "match
// everything") so a typo in the operator's config doesn't open
// the gate.
type AllowedSNDUD struct {
	CI      byte
	Address byte
}

// Matches reports whether this AllowedSNDUD permits the given
// frame. Caller must verify the frame is a SND_UD before
// dispatching here.
func (a AllowedSNDUD) Matches(f mbwire.Frame) bool {
	if a == (AllowedSNDUD{}) {
		// Empty struct matches nothing — guards against operators
		// who accidentally configure {CI: 0, Address: 0} thinking
		// it means "wildcard all" (which would make the gate
		// ineffective).
		return false
	}
	if a.CI != 0 && a.CI != f.CI {
		return false
	}
	if a.Address != 0 && a.Address != f.Address {
		return false
	}
	return true
}

// AllowlistHash returns the deterministic SHA-256 of the
// allowlist. Entries are sorted by (CI, Address) before hashing
// so the operator's dry-run token is stable regardless of input
// order.
func AllowlistHash(target string, allowed []AllowedSNDUD) [32]byte {
	sorted := append([]AllowedSNDUD(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CI != sorted[j].CI {
			return sorted[i].CI < sorted[j].CI
		}
		return sorted[i].Address < sorted[j].Address
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [2]byte
	for _, a := range sorted {
		buf[0] = a.CI
		buf[1] = a.Address
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises
// the proxy session.
func SessionMutation(target string, allowed []AllowedSNDUD) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "mbustcp",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// AllowlistHashWithGeneration is the v1.17-style cookie variant.
// generation == 0 → equals AllowlistHash. Mirrors the design used
// for modbus/iax2/sip/bacnet/cwmp/knxip.
func AllowlistHashWithGeneration(target string, allowed []AllowedSNDUD, generation uint32) [32]byte {
	if generation == 0 {
		return AllowlistHash(target, allowed)
	}
	sorted := append([]AllowedSNDUD(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CI != sorted[j].CI {
			return sorted[i].CI < sorted[j].CI
		}
		return sorted[i].Address < sorted[j].Address
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [2]byte
	for _, a := range sorted {
		buf[0] = a.CI
		buf[1] = a.Address
		_, _ = h.Write(buf[:])
	}
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], generation)
	_, _ = h.Write([]byte{0xFC})
	_, _ = h.Write(u32[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithGeneration builds the confirm.Mutation with
// the token-generation cookie.
func SessionMutationWithGeneration(target string, allowed []AllowedSNDUD, generation uint32) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "mbustcp",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithGeneration(target, allowed, generation),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// M-Bus over TCP fail-closed proxy.
type WriteGatedHandler struct {
	Target  string
	Allowed []AllowedSNDUD
	// TokenGeneration is the v1.17-style cookie. Default 0
	// preserves the v1.56 base hash.
	TokenGeneration uint32
	Deriver         confirm.KeyDeriver
	Auditor         confirm.Auditor
	SessionConfirm  confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutationWithGeneration(h.Target, h.Allowed, h.TokenGeneration)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("mbustcp: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler. M-Bus over TCP is a
// straight stream: each frame is consumed by the wire-package
// ReadFrame parser. Allowed frames forward; refused frames drop
// silently (the meter's master will retransmit and then time
// out, surfacing a clean failure to the client).
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	if h.Recorder != nil {
		client = h.Recorder.WrapClient(client)
		upstream = h.Recorder.WrapUpstream(upstream)
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream) }()
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

// forward reads frames from the client side and routes each per
// policy.
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer) error {
	for {
		f, err := mbwire.ReadFrame(client)
		if err != nil {
			return err
		}
		if !h.shouldForward(f) {
			// Silent drop — see package doc for refusal rationale.
			continue
		}
		if _, werr := upstream.Write(f.Raw); werr != nil {
			return werr
		}
	}
}

// shouldForward returns true when the frame is a legitimate
// read/keep-alive OR a SND_UD that matches an AllowedSNDUD
// entry.
func (h *WriteGatedHandler) shouldForward(f mbwire.Frame) bool {
	if f.IsACK {
		// Master clients rarely send ACK; meters do. The forward
		// direction is master→meter, so an ACK here is
		// extraordinary but not mutating — pass it through.
		return true
	}
	if f.IsAlwaysSafeControl() {
		return true
	}
	if f.IsSNDUD() {
		return h.sndUDAllowed(f)
	}
	// Unknown / other control bytes: refuse. The gate doesn't
	// pass what it can't classify.
	return false
}

// sndUDAllowed evaluates a SND_UD frame against the allowlist.
func (h *WriteGatedHandler) sndUDAllowed(f mbwire.Frame) bool {
	for _, a := range h.Allowed {
		if a.Matches(f) {
			return true
		}
	}
	return false
}
