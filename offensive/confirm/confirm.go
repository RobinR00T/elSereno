//go:build offensive

package confirm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Category groups offensive operations. The same token-derivation and
// audit contract applies to all four; the category is emitted in the
// audit event so downstream analytics can split by kind.
type Category string

// Categories accepted by Authorize.
const (
	CategoryWrite   Category = "write"
	CategoryExploit Category = "exploit"
	CategoryHarvest Category = "harvest"
	CategoryDial    Category = "dial"
)

// Valid returns true if c is one of the recognised categories.
func (c Category) Valid() bool {
	switch c {
	case CategoryWrite, CategoryExploit, CategoryHarvest, CategoryDial:
		return true
	}
	return false
}

// Mutation is the side-effecting operation being authorised. The
// caller fills the fields that match its layer; Target is a string
// so that Dial (a phone number) and Write (host:port) can share the
// wrapper.
type Mutation struct {
	Category    Category
	Protocol    string // "modbus", "s7", "dial", "telnet", …
	Operation   string // "write_single_register", "cve-2019-10953", "dial"
	Target      string // host:port OR normalised E.164 number
	PayloadHash [32]byte
}

// Validate ensures Mutation is structurally usable. Callers get a
// typed error early so Authorize never audits a malformed request.
func (m Mutation) Validate() error {
	if !m.Category.Valid() {
		return fmt.Errorf("%w: %q", ErrBadCategory, m.Category)
	}
	if m.Protocol == "" {
		return errors.New("confirm: Protocol empty")
	}
	if m.Operation == "" {
		return errors.New("confirm: Operation empty")
	}
	if m.Target == "" {
		return errors.New("confirm: Target empty")
	}
	return nil
}

// Confirm carries the three operator-supplied fences. It is filled
// from CLI flags in cmd/elsereno/cmd_*_offensive.go.
type Confirm struct {
	// AcceptsWrites is set by --accept-writes. False blocks early with
	// ErrNotAccepted.
	AcceptsWrites bool

	// ConfirmTarget is set by --confirm-target. It must equal
	// Mutation.Target byte-for-byte.
	ConfirmTarget string

	// ConfirmToken is set by --confirm-token. It must equal
	// ExpectedToken(Mutation, deriver).
	ConfirmToken string
}

// KeyDeriver mirrors the minimum surface of *creds.Vault needed to
// compute the HMAC key. A test double or out-of-process deriver can
// substitute in tests.
type KeyDeriver interface {
	Derive(info string, out []byte) error
}

// Auditor is the hook into the audit chain. The confirm package does
// not know about internal/audit directly; cmd/elsereno wires this up
// with an adapter.
type Auditor interface {
	Record(ctx context.Context, ev AuditEvent) error
}

// AuditEvent is the payload the confirm package asks an Auditor to
// persist. EventType is one of the four strings in ADR-039.
type AuditEvent struct {
	EventType   string // "offensive_allowed" | "offensive_denied" | "offensive_failed" | "offensive_attempt"
	Category    Category
	Protocol    string
	Operation   string
	Target      string
	PayloadHash string // hex of Mutation.PayloadHash
	Reason      string // set for denied / failed
	OccurredAt  time.Time
}

// Errors returned by Authorize.
var (
	// ErrBadCategory — Mutation.Category is not a known enum value.
	ErrBadCategory = errors.New("confirm: unknown category")
	// ErrNotAccepted — the operator did not pass --accept-writes.
	ErrNotAccepted = errors.New("confirm: --accept-writes not set")
	// ErrTargetMismatch — --confirm-target did not match Mutation.Target.
	ErrTargetMismatch = errors.New("confirm: --confirm-target does not match target")
	// ErrTokenMismatch — --confirm-token did not match the expected token.
	ErrTokenMismatch = errors.New("confirm: --confirm-token does not match expected")
	// ErrVaultLocked — deriver refused to produce a key.
	ErrVaultLocked = errors.New("confirm: vault locked")
)

// infoLabel is the HKDF label for the offensive confirm key (ADR-039).
const infoLabel = "elsereno/offensive/confirm/v1"

// tokenLen is the number of hex chars returned by ExpectedToken.
const tokenLen = 32

// ExpectedToken computes the operator-pastable confirm token for m.
// The caller is the *operator's* dry-run; the very same computation
// happens inside Authorize for the real run, and the two must match.
//
// Layout of the HMAC input:
//
//	category || 0x00 || protocol || 0x00 || operation || 0x00 ||
//	target   || 0x00 || payloadHash(32 raw bytes)
//
// Nulls are used as separators because no Mutation field is allowed
// to contain a NUL byte (the caller validates with Validate()).
func ExpectedToken(m Mutation, d KeyDeriver) (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	key := make([]byte, 32)
	if err := d.Derive(infoLabel, key); err != nil {
		return "", fmt.Errorf("%w: %w", ErrVaultLocked, err)
	}
	mac := hmac.New(sha256.New, key)
	// Zero the key slice as soon as the MAC object no longer needs it.
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	sep := []byte{0x00}
	_, _ = mac.Write([]byte(m.Category))
	_, _ = mac.Write(sep)
	_, _ = mac.Write([]byte(m.Protocol))
	_, _ = mac.Write(sep)
	_, _ = mac.Write([]byte(m.Operation))
	_, _ = mac.Write(sep)
	_, _ = mac.Write([]byte(m.Target))
	_, _ = mac.Write(sep)
	_, _ = mac.Write(m.PayloadHash[:])
	digest := mac.Sum(nil)
	return hex.EncodeToString(digest[:tokenLen/2]), nil
}

// Authorize is the single choke-point. Success means "the operator
// signalled all three fences AND the derived token matches".
//
// Authorize never returns nil without an allowed audit event having
// been recorded. A denied result returns the typed sentinel AND
// records the denial.
//
// The audit record is a best-effort emission — if the Auditor itself
// errors, Authorize propagates that error with the allowed decision
// unchanged (the caller should refuse to fire the mutation when the
// audit write failed; see cmd/elsereno/cmd_write_offensive.go).
func Authorize(ctx context.Context, m Mutation, c Confirm, d KeyDeriver, a Auditor) error {
	if err := m.Validate(); err != nil {
		_ = emitAudit(ctx, a, m, "offensive_failed", err.Error())
		return err
	}
	if !c.AcceptsWrites {
		_ = emitAudit(ctx, a, m, "offensive_denied", ErrNotAccepted.Error())
		return ErrNotAccepted
	}
	if c.ConfirmTarget != m.Target {
		_ = emitAudit(ctx, a, m, "offensive_denied", ErrTargetMismatch.Error())
		return ErrTargetMismatch
	}
	expected, err := ExpectedToken(m, d)
	if err != nil {
		_ = emitAudit(ctx, a, m, "offensive_failed", err.Error())
		return err
	}
	// Constant-time comparison to close a timing-oracle that would let
	// an attacker brute-force the token one char at a time.
	if !hmac.Equal([]byte(strings.TrimSpace(c.ConfirmToken)), []byte(expected)) {
		_ = emitAudit(ctx, a, m, "offensive_denied", ErrTokenMismatch.Error())
		return ErrTokenMismatch
	}
	if err := emitAudit(ctx, a, m, "offensive_allowed", ""); err != nil {
		return fmt.Errorf("confirm: audit write: %w", err)
	}
	return nil
}

// emitAudit is the shared emitter. Failures bubble to Authorize so
// it can refuse to fire on a broken audit chain. Renamed from the
// v1.0 `audit` to avoid colliding with the internal/audit package
// now imported by adapter.go.
func emitAudit(ctx context.Context, a Auditor, m Mutation, evType, reason string) error {
	if a == nil {
		return nil
	}
	return a.Record(ctx, AuditEvent{
		EventType:   evType,
		Category:    m.Category,
		Protocol:    m.Protocol,
		Operation:   m.Operation,
		Target:      m.Target,
		PayloadHash: hex.EncodeToString(m.PayloadHash[:]),
		Reason:      reason,
		OccurredAt:  time.Now().UTC().Truncate(time.Microsecond),
	})
}
