package backup_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	"local/elsereno/internal/backup"
)

// stubDeriver emulates *creds.Vault.Derive with a static "master"
// so tests are deterministic.
type stubDeriver struct{ master string }

func (s *stubDeriver) Derive(info string, out []byte) error {
	r := hkdf.New(sha256.New, []byte(s.master), nil, []byte(info))
	_, err := io.ReadFull(r, out)
	return err
}

func sampleFiles() []backup.File {
	return []backup.File{
		{Name: "vault.v1.bin", Body: []byte("encrypted-vault-bytes"), Mode: 0o600, ModTime: time.Unix(1_700_000_000, 0).UTC()},
		{Name: "findings.json", Body: bytes.Repeat([]byte("finding"), 128), ModTime: time.Unix(1_700_000_010, 0).UTC()},
	}
}

func TestRoundTrip(t *testing.T) {
	d := &stubDeriver{master: "k"}
	files := sampleFiles()
	var buf bytes.Buffer
	if err := backup.Create(&buf, d, files); err != nil {
		t.Fatal(err)
	}
	got, err := backup.Restore(&buf, d)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(got) != len(files) {
		t.Fatalf("count: got %d, want %d", len(got), len(files))
	}
	for i := range got {
		if got[i].Name != files[i].Name {
			t.Errorf("%d: name %q vs %q", i, got[i].Name, files[i].Name)
		}
		if !bytes.Equal(got[i].Body, files[i].Body) {
			t.Errorf("%d: body mismatch", i)
		}
	}
}

func TestTamper_DetectedByAEAD(t *testing.T) {
	d := &stubDeriver{master: "k"}
	var buf bytes.Buffer
	if err := backup.Create(&buf, d, sampleFiles()); err != nil {
		t.Fatal(err)
	}
	blob := buf.Bytes()
	// Flip a byte deep in the ciphertext (past header 4+1+16+12=33).
	blob[60] ^= 0xAA
	_, err := backup.Restore(bytes.NewReader(blob), d)
	if !errors.Is(err, backup.ErrTampered) {
		t.Fatalf("want ErrTampered, got %v", err)
	}
}

func TestTamper_SaltSwapStillFails(t *testing.T) {
	d := &stubDeriver{master: "k"}
	var a, b bytes.Buffer
	_ = backup.Create(&a, d, sampleFiles())
	_ = backup.Create(&b, d, sampleFiles())
	// Build a hybrid: take envelope A's header up through salt but
	// B's nonce + ciphertext. The key derived from A's salt will
	// not decrypt B's ciphertext.
	aBytes := a.Bytes()
	bBytes := b.Bytes()
	hybrid := make([]byte, 0, len(bBytes))
	hybrid = append(hybrid, aBytes[:5+backup.SaltLen]...)
	hybrid = append(hybrid, bBytes[5+backup.SaltLen:]...)
	_, err := backup.Restore(bytes.NewReader(hybrid), d)
	if !errors.Is(err, backup.ErrTampered) {
		t.Fatalf("want ErrTampered on salt swap, got %v", err)
	}
}

func TestWrongDeriverFails(t *testing.T) {
	writer := &stubDeriver{master: "good"}
	reader := &stubDeriver{master: "bad"}
	var buf bytes.Buffer
	if err := backup.Create(&buf, writer, sampleFiles()); err != nil {
		t.Fatal(err)
	}
	_, err := backup.Restore(&buf, reader)
	if !errors.Is(err, backup.ErrTampered) {
		t.Fatalf("want ErrTampered on wrong key, got %v", err)
	}
}

func TestBadMagic(t *testing.T) {
	// Give the parser enough bytes to pass the length check so we
	// actually test the magic-byte rejection, not the truncation one.
	payload := make([]byte, 5+backup.SaltLen+backup.NonceLen+16)
	copy(payload, []byte("NOPE")) // bad magic
	_, err := backup.Restore(bytes.NewReader(payload), &stubDeriver{master: "k"})
	if !errors.Is(err, backup.ErrBadMagic) {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	d := &stubDeriver{master: "k"}
	var buf bytes.Buffer
	_ = backup.Create(&buf, d, sampleFiles())
	blob := buf.Bytes()
	blob[4] = 99 // corrupt version byte
	_, err := backup.Restore(bytes.NewReader(blob), d)
	if !errors.Is(err, backup.ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestTruncated(t *testing.T) {
	_, err := backup.Restore(bytes.NewReader([]byte{0x45, 0x4C}), &stubDeriver{master: "k"})
	if !errors.Is(err, backup.ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
}

func TestTwoBackupsDifferByDefault(t *testing.T) {
	// Different salt + nonce each call → two byte-identical input
	// sets produce different ciphertexts (IND-CPA requirement).
	d := &stubDeriver{master: "k"}
	var a, b bytes.Buffer
	_ = backup.Create(&a, d, sampleFiles())
	_ = backup.Create(&b, d, sampleFiles())
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two backups of the same data should not be byte-identical")
	}
}

func TestEmptyFilesAllowed(t *testing.T) {
	d := &stubDeriver{master: "k"}
	var buf bytes.Buffer
	if err := backup.Create(&buf, d, nil); err != nil {
		t.Fatalf("empty create: %v", err)
	}
	got, err := backup.Restore(&buf, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 files, got %d", len(got))
	}
}
