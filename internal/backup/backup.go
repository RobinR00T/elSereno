// Package backup emits tamper-evident, encrypted backups of the
// vault (and, once the DB writer lands, of findings + audit). The
// envelope is:
//
//	[magic 4][version 1][salt 16][nonce 12][ciphertext+tag]
//
// The encryption key is derived via HKDF-SHA256 from the vault
// master key with info "elsereno/backup/v1" and the per-archive
// salt. AES-256-GCM AEAD fails closed on any byte tamper.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
)

// Envelope constants. Changing any of them forces a version bump
// because existing archives become unreadable.
const (
	// Magic spells "ELSB" (EL Sereno Backup).
	Magic uint32 = 0x454C5342
	// Version is the on-disk envelope version. Bump when the field
	// layout changes; `Restore` rejects mismatched versions.
	Version uint8 = 1
	// SaltLen + NonceLen + keyLen follow NIST / RFC 5869 sizes.
	SaltLen  = 16
	NonceLen = 12
	keyLen   = 32
	hkdfInfo = "elsereno/backup/v1"
)

// Errors returned by the envelope parser.
var (
	// ErrBadMagic signals the input is not an ElSereno backup.
	ErrBadMagic = errors.New("backup: bad magic (not an ElSereno backup)")
	// ErrUnsupportedVersion — the envelope uses a version this
	// binary does not support.
	ErrUnsupportedVersion = errors.New("backup: unsupported envelope version")
	// ErrTruncated — the archive ended mid-field.
	ErrTruncated = errors.New("backup: archive truncated")
	// ErrTampered — AEAD verification failed (bit-flip, wrong key).
	ErrTampered = errors.New("backup: tamper or wrong key")
)

// KeyDeriver is the minimum surface Create / Restore need from the
// vault. *creds.Vault satisfies it.
type KeyDeriver interface {
	Derive(info string, out []byte) error
}

// File is one entry in the archive. Name is the path stored inside
// the tar; Body is the raw content. Mode + ModTime default to 0o600
// + time.Now().UTC() when zero.
type File struct {
	Name    string
	Body    []byte
	Mode    int64
	ModTime time.Time
}

// Create writes the encrypted backup envelope to w. files are tar +
// gzip-compressed before encryption. The envelope layout is:
//
//	magic(4) || version(1) || salt(16) || nonce(12) || ciphertext
//
// The salt lets each backup derive a fresh data key from the same
// vault master, so two backups of the same data are never
// byte-identical.
func Create(w io.Writer, d KeyDeriver, files []File) error {
	payload, err := marshalArchive(files)
	if err != nil {
		return err
	}
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("backup: salt: %w", err)
	}
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("backup: nonce: %w", err)
	}
	key, err := deriveKey(d, salt)
	if err != nil {
		return err
	}
	defer zero(key)

	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, payload, saltAAD(salt))

	hdr := make([]byte, 0, 4+1+SaltLen+NonceLen)
	hdr = append(hdr,
		byte((Magic>>24)&0xFF), byte((Magic>>16)&0xFF), byte((Magic>>8)&0xFF), byte(Magic&0xFF),
		Version,
	)
	hdr = append(hdr, salt...)
	hdr = append(hdr, nonce...)
	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("backup: write header: %w", err)
	}
	if _, err := w.Write(ct); err != nil {
		return fmt.Errorf("backup: write body: %w", err)
	}
	return nil
}

// Restore reads the envelope from r and returns the decrypted file
// list. Any bit tamper yields ErrTampered; wrong vault yields the
// same error (AEAD cannot distinguish).
func Restore(r io.Reader, d KeyDeriver) ([]File, error) {
	all, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("backup: read: %w", err)
	}
	if len(all) < 4+1+SaltLen+NonceLen {
		return nil, ErrTruncated
	}
	if magic := uint32(all[0])<<24 | uint32(all[1])<<16 | uint32(all[2])<<8 | uint32(all[3]); magic != Magic {
		return nil, fmt.Errorf("%w: 0x%08x", ErrBadMagic, magic)
	}
	if v := all[4]; v != Version {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, v, Version)
	}
	salt := all[5 : 5+SaltLen]
	nonce := all[5+SaltLen : 5+SaltLen+NonceLen]
	ct := all[5+SaltLen+NonceLen:]

	key, err := deriveKey(d, salt)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	payload, err := aead.Open(nil, nonce, ct, saltAAD(salt))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTampered, err)
	}
	return unmarshalArchive(payload)
}

func deriveKey(d KeyDeriver, salt []byte) ([]byte, error) {
	// We inject the per-archive salt via a two-stage derivation:
	// master --HKDF(info=hkdfInfo)--> intermediate
	// intermediate --HKDF(info=salt)--> 32-byte data key.
	intermediate := make([]byte, keyLen)
	if err := d.Derive(hkdfInfo, intermediate); err != nil {
		return nil, fmt.Errorf("backup: derive: %w", err)
	}
	defer zero(intermediate)
	r := hkdf.New(sha256.New, intermediate, salt, []byte(hkdfInfo))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("backup: hkdf: %w", err)
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup: aes: %w", err)
	}
	return cipher.NewGCM(block)
}

// saltAAD binds the salt into the AEAD's additional-authenticated-
// data so an attacker that swaps the salt bytes is caught.
func saltAAD(salt []byte) []byte { return append([]byte("elsereno:backup:"), salt...) }

// marshalArchive serialises `files` as tar+gzip bytes.
func marshalArchive(files []File) ([]byte, error) {
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	for _, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o600
		}
		mtime := f.ModTime
		if mtime.IsZero() {
			mtime = time.Now().UTC()
		}
		hdr := &tar.Header{
			Name:     f.Name,
			Mode:     mode,
			Size:     int64(len(f.Body)),
			ModTime:  mtime,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("backup: tar header %s: %w", f.Name, err)
		}
		if _, err := tw.Write(f.Body); err != nil {
			return nil, fmt.Errorf("backup: tar body %s: %w", f.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("backup: tar close: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("backup: gzip close: %w", err)
	}
	return gzBuf.Bytes(), nil
}

// unmarshalArchive reverses marshalArchive.
func unmarshalArchive(payload []byte) ([]File, error) {
	gr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("backup: gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	var out []File
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("backup: tar next: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("backup: tar body %s: %w", hdr.Name, err)
		}
		out = append(out, File{
			Name:    hdr.Name,
			Body:    body,
			Mode:    hdr.Mode,
			ModTime: hdr.ModTime,
		})
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
