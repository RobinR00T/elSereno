package creds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Magic is the file-format identifier. Bumping "v1" is a breaking
// change that requires a migration path.
const Magic = "elsereno.vault.v1"

// FileMode is the umask-respecting permission set for the vault file.
// 0600 matches the secret-on-disk discipline (PITF-032).
const FileMode = 0o600

// fileFormat is the on-disk JSON document. Binary fields are
// base64-encoded so the file remains grep-safe and easy to inspect
// with plain tools.
type fileFormat struct {
	Magic    string             `json:"magic"`
	Version  int                `json:"version"`
	Created  time.Time          `json:"created"`
	Envelope envelopeJSON       `json:"envelope"`
	Entries  map[string]entryJS `json:"entries"`
}

type envelopeJSON struct {
	Salt     string `json:"salt"`
	Nonce    string `json:"nonce"`
	Sentinel string `json:"sentinel"`
}

type entryJS struct {
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	CreatedAt  time.Time `json:"created_at"`
	RotatedAt  time.Time `json:"rotated_at,omitempty"`
}

// SaveToFile serialises the vault state to path with 0600 permissions.
// Callers are responsible for calling it at meaningful checkpoints
// (after Init, after Store/Rotate/Purge). We do NOT auto-persist on
// every mutation to keep the surface explicit.
func (v *Vault) SaveToFile(path string) error {
	v.mu.RLock()
	doc := fileFormat{
		Magic:   Magic,
		Version: 1,
		Created: v.state.Created,
		Envelope: envelopeJSON{
			Salt:     base64.StdEncoding.EncodeToString(v.state.Salt),
			Nonce:    base64.StdEncoding.EncodeToString(v.state.Nonce),
			Sentinel: base64.StdEncoding.EncodeToString(v.state.Sentinel),
		},
		Entries: make(map[string]entryJS, len(v.entries)),
	}
	for name, e := range v.entries {
		doc.Entries[name] = entryJS{
			Nonce:      base64.StdEncoding.EncodeToString(e.nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(e.ciphertext),
			CreatedAt:  e.createdAt,
			RotatedAt:  e.rotatedAt,
		}
	}
	v.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creds: mkdir %q: %w", filepath.Dir(path), err)
	}

	// Write to a tmp file + rename for atomicity.
	tmp := path + ".tmp"
	// #nosec G304 -- caller-supplied vault path; operator controls it
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, FileMode)
	if err != nil {
		return fmt.Errorf("creds: open %q: %w", tmp, err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		_ = f.Close()
		return fmt.Errorf("creds: encode: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("creds: close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("creds: rename: %w", err)
	}
	return nil
}

// LoadFromFile populates v.state and v.entries from path. The vault is
// marked initialised but locked; callers MUST call Unlock next.
func (v *Vault) LoadFromFile(path string) error {
	b, err := os.ReadFile(path) // #nosec G304 -- caller-supplied vault path
	if err != nil {
		return fmt.Errorf("creds: read %q: %w", path, err)
	}
	var doc fileFormat
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("creds: parse %q: %w", path, err)
	}
	if doc.Magic != Magic {
		return fmt.Errorf("creds: bad magic %q in %q; expected %q", doc.Magic, path, Magic)
	}

	salt, err := base64.StdEncoding.DecodeString(doc.Envelope.Salt)
	if err != nil {
		return fmt.Errorf("creds: decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(doc.Envelope.Nonce)
	if err != nil {
		return fmt.Errorf("creds: decode nonce: %w", err)
	}
	sentinel, err := base64.StdEncoding.DecodeString(doc.Envelope.Sentinel)
	if err != nil {
		return fmt.Errorf("creds: decode sentinel: %w", err)
	}

	entries := make(map[string]secretEntry, len(doc.Entries))
	for name, e := range doc.Entries {
		n, err := base64.StdEncoding.DecodeString(e.Nonce)
		if err != nil {
			return fmt.Errorf("creds: decode entry %q nonce: %w", name, err)
		}
		c, err := base64.StdEncoding.DecodeString(e.Ciphertext)
		if err != nil {
			return fmt.Errorf("creds: decode entry %q ct: %w", name, err)
		}
		entries[name] = secretEntry{
			ciphertext: c,
			nonce:      n,
			createdAt:  e.CreatedAt,
			rotatedAt:  e.RotatedAt,
		}
	}

	v.mu.Lock()
	v.state = VaultState{Salt: salt, Nonce: nonce, Sentinel: sentinel, Created: doc.Created}
	v.entries = entries
	v.initialised = true
	v.unlocked = false
	v.mu.Unlock()
	return nil
}

// DefaultVaultPath returns $HOME/.elsereno/vault.v1.bin. Callers that
// need the value should cache it per process.
func DefaultVaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("creds: home: %w", err)
	}
	return filepath.Join(home, ".elsereno", "vault.v1.bin"), nil
}

// ErrFileExists is returned by InitToFile when the target path already
// exists. Callers must decide whether to back up and re-init.
var ErrFileExists = errors.New("creds: vault file already exists")

// InitToFile is the composed "init + persist" primitive. It returns
// ErrFileExists if the path already exists (PITF-021 — never silently
// overwrite critical state). Callers opt in to overwrite via a wrapper.
func (v *Vault) InitToFile(ctx context.Context, passphrase []byte, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %s", ErrFileExists, path)
	}
	if err := v.Init(ctx, passphrase); err != nil {
		return err
	}
	return v.SaveToFile(path)
}
