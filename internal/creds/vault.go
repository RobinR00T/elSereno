package creds

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters per ADR-018. These are tuned for workstation use:
// 64 MiB memory, 4 threads, 3 iterations. Changing them breaks
// compatibility with existing vault files; a migration path is part of
// the wider F1 scope but not landed here.
const (
	Argon2Time    uint32 = 3
	Argon2Memory  uint32 = 64 * 1024 // KiB
	Argon2Threads uint8  = 4
	Argon2KeyLen  uint32 = 32 // AES-256

	NonceLen = 12 // GCM
	SaltLen  = 16

	// VaultStateFile is the name inside `elsereno.vault_dir` where the
	// encrypted master-key envelope lives. Secrets are stored by name in
	// adjacent files or in a DB table (creds_vault); the F1 chunk 2
	// scaffold stores them only in memory plus an envelope file that the
	// storage package promotes to DB persistence.
	VaultStateFile = "vault.v1.bin"
)

// ErrNotInitialised is returned when an operation requires an existing
// vault but none is present.
var ErrNotInitialised = errors.New("creds: vault not initialised (run `elsereno vault init`)")

// ErrAlreadyInitialised is returned when Init is called against a vault
// that already exists (PITF-021 — never auto-overwrite critical state).
var ErrAlreadyInitialised = errors.New("creds: vault already initialised")

// ErrLocked is returned when an operation requires the master key but
// the vault is locked.
var ErrLocked = errors.New("creds: vault is locked (run `elsereno vault unlock`)")

// ErrBadPassphrase is returned when Unlock fails to authenticate the
// envelope's GCM tag.
var ErrBadPassphrase = errors.New("creds: bad passphrase")

// ErrNameNotFound is returned by Retrieve/Rotate/Purge when the name
// has not been stored.
var ErrNameNotFound = errors.New("creds: name not found")

// Vault is the in-process vault. It is safe for concurrent use but
// callers should treat it as a singleton per process (memguard
// allocations are process-wide anyway).
type Vault struct {
	mu sync.RWMutex

	state       VaultState
	masterKey   *memguard.LockedBuffer // nil when locked
	initialised bool
	unlocked    bool

	entries map[string]secretEntry
}

// VaultState is the on-disk envelope. Exported so that the storage
// adapter (file-based here; creds_vault table in F2) can marshal it.
type VaultState struct {
	Salt     []byte    // Argon2id salt
	Nonce    []byte    // GCM nonce for the sentinel plaintext
	Sentinel []byte    // GCM(derived, Nonce, sentinel) — verifies passphrase
	Created  time.Time // RFC 3339 μs
}

type secretEntry struct {
	ciphertext []byte
	nonce      []byte
	createdAt  time.Time
	rotatedAt  time.Time
}

// New returns an unlocked-less Vault; callers must then Init or
// Unlock to make it usable.
func New() *Vault {
	return &Vault{
		entries: make(map[string]secretEntry),
	}
}

// Status reports whether the vault is initialised and/or unlocked.
type Status struct {
	Initialised bool
	Unlocked    bool
}

// Status returns the current vault status.
func (v *Vault) Status() Status {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return Status{Initialised: v.initialised, Unlocked: v.unlocked}
}

// Init creates a fresh vault from a passphrase. It refuses to run if
// the vault is already initialised in-memory (PITF-021); callers that
// persist to disk MUST check file presence independently before
// invoking Init.
func (v *Vault) Init(_ context.Context, passphrase []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.initialised {
		return ErrAlreadyInitialised
	}

	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("creds: salt: %w", err)
	}

	derived, buf, err := deriveMaster(passphrase, salt)
	if err != nil {
		return err
	}

	// Sentinel is a fixed 16-byte tag encrypted with the master key so
	// Unlock can verify the passphrase without decrypting actual secrets.
	sentinel := []byte("elsereno-vault1!")
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		buf.Destroy()
		return fmt.Errorf("creds: nonce: %w", err)
	}
	cipherT, err := gcmSeal(derived, nonce, sentinel, nil)
	if err != nil {
		buf.Destroy()
		return err
	}

	v.state = VaultState{
		Salt:     salt,
		Nonce:    nonce,
		Sentinel: cipherT,
		Created:  time.Now().UTC().Truncate(time.Microsecond),
	}
	v.masterKey = buf
	v.initialised = true
	v.unlocked = true
	return nil
}

// Load restores a previously initialised state without unlocking. Used
// by the storage adapter when a vault envelope exists on disk.
func (v *Vault) Load(state VaultState) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.state = state
	v.initialised = true
	v.unlocked = false
}

// Unlock derives the master key and verifies it against the stored
// sentinel.
func (v *Vault) Unlock(_ context.Context, passphrase []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.initialised {
		return ErrNotInitialised
	}
	if v.unlocked {
		return nil
	}

	derived, buf, err := deriveMaster(passphrase, v.state.Salt)
	if err != nil {
		return err
	}

	if _, err := gcmOpen(derived, v.state.Nonce, v.state.Sentinel, nil); err != nil {
		buf.Destroy()
		return ErrBadPassphrase
	}

	v.masterKey = buf
	v.unlocked = true
	return nil
}

// Lock zeroises the master key. Reversible with a subsequent Unlock.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masterKey != nil {
		v.masterKey.Destroy()
		v.masterKey = nil
	}
	v.unlocked = false
}

// Derive implements HKDF-SHA256(masterKey, info). The caller chooses a
// distinct `info` label per purpose (ADR-017 uses "elsereno/csrf/v1").
func (v *Vault) Derive(info string, out []byte) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.unlocked || v.masterKey == nil {
		return ErrLocked
	}
	// HKDF needs access to the plaintext key; memguard makes that
	// explicit via Bytes(). We copy into a short-lived local slice that
	// leaves the function only as derived bytes in out.
	key := v.masterKey.Bytes()
	r := hkdf.New(sha256new, key, nil, []byte(info))
	_, err := io.ReadFull(r, out)
	return err
}

// Store encrypts `plaintext` under the master key with a fresh GCM
// nonce. The entry is held in memory; persistence is a storage-adapter
// concern (creds_vault table in chunk-N+1).
func (v *Vault) Store(_ context.Context, name string, plaintext []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.unlocked || v.masterKey == nil {
		return ErrLocked
	}
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("creds: nonce: %w", err)
	}
	ct, err := gcmSeal(v.masterKey.Bytes(), nonce, plaintext, []byte(name))
	if err != nil {
		return err
	}
	e := secretEntry{
		ciphertext: ct,
		nonce:      nonce,
		createdAt:  time.Now().UTC().Truncate(time.Microsecond),
	}
	if prev, ok := v.entries[name]; ok {
		e.createdAt = prev.createdAt
		e.rotatedAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	v.entries[name] = e
	return nil
}

// Retrieve returns the decrypted plaintext for `name`. Callers must
// wipe the returned slice after use.
func (v *Vault) Retrieve(_ context.Context, name string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.unlocked || v.masterKey == nil {
		return nil, ErrLocked
	}
	e, ok := v.entries[name]
	if !ok {
		return nil, ErrNameNotFound
	}
	pt, err := gcmOpen(v.masterKey.Bytes(), e.nonce, e.ciphertext, []byte(name))
	if err != nil {
		return nil, fmt.Errorf("creds: open %q: %w", name, err)
	}
	return pt, nil
}

// Rotate re-encrypts `name` with the supplied new plaintext.
func (v *Vault) Rotate(ctx context.Context, name string, plaintext []byte) error {
	v.mu.RLock()
	_, ok := v.entries[name]
	v.mu.RUnlock()
	if !ok {
		return ErrNameNotFound
	}
	return v.Store(ctx, name, plaintext)
}

// Purge removes `name` and zeroises the ciphertext in place.
func (v *Vault) Purge(_ context.Context, name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.unlocked {
		return ErrLocked
	}
	e, ok := v.entries[name]
	if !ok {
		return ErrNameNotFound
	}
	for i := range e.ciphertext {
		e.ciphertext[i] = 0
	}
	delete(v.entries, name)
	return nil
}

// List returns the names of the stored secrets in undefined order.
func (v *Vault) List() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if !v.unlocked {
		return nil
	}
	out := make([]string, 0, len(v.entries))
	for name := range v.entries {
		out = append(out, name)
	}
	return out
}

// EntryMetadata is the non-sensitive view of a stored credential
// (name + timestamps, no plaintext or ciphertext). Returned by
// Vault.Metadata for `creds show` without --reveal.
type EntryMetadata struct {
	Name      string
	CreatedAt time.Time
	RotatedAt time.Time
}

// Metadata returns name/createdAt/rotatedAt without revealing the
// plaintext (creds show without --reveal).
func (v *Vault) Metadata(name string) (EntryMetadata, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.entries[name]
	if !ok {
		return EntryMetadata{}, ErrNameNotFound
	}
	return EntryMetadata{Name: name, CreatedAt: e.createdAt, RotatedAt: e.rotatedAt}, nil
}

// deriveMaster runs Argon2id on the supplied passphrase and seals the
// output into a memguard.LockedBuffer. The returned []byte aliases the
// buffer; callers must not retain it after buf.Destroy().
func deriveMaster(passphrase, salt []byte) ([]byte, *memguard.LockedBuffer, error) {
	if len(passphrase) == 0 {
		return nil, nil, fmt.Errorf("creds: empty passphrase")
	}
	derived := argon2.IDKey(passphrase, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	buf := memguard.NewBufferFromBytes(derived)
	return buf.Bytes(), buf, nil
}

// Envelope encodes VaultState for simple serialisation (hex-encoded
// bytes + RFC 3339 timestamp). The storage adapter decides on-wire
// format; this helper is useful for human-readable exports.
func (s VaultState) Envelope() map[string]string {
	return map[string]string{
		"salt":     hex.EncodeToString(s.Salt),
		"nonce":    hex.EncodeToString(s.Nonce),
		"sentinel": hex.EncodeToString(s.Sentinel),
		"created":  s.Created.Format(time.RFC3339Nano),
	}
}

// gcmSeal wraps crypto/cipher.AEAD.Seal with a fresh GCM per call.
func gcmSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creds: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creds: gcm: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// gcmOpen wraps crypto/cipher.AEAD.Open with a fresh GCM per call.
func gcmOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creds: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creds: gcm: %w", err)
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("creds: gcm open: %w", err)
	}
	return pt, nil
}
