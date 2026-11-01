package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/audit"
)

var testMACKey = []byte("test-audit-mac-key-32-bytes-aaaa")

func tmpAuditPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.jsonl")
}

func appendN(t *testing.T, w audit.Writer, types ...audit.EventType) {
	t.Helper()
	for _, et := range types {
		if _, err := w.Append(context.Background(), audit.Entry{EventType: et, Actor: "ci"}); err != nil {
			t.Fatalf("append %s: %v", et, err)
		}
	}
}

// TestKeyed_VerifyRequiresKey: a keyed (HMAC) chain verifies with the
// key and cannot be verified without it (or with the wrong one).
func TestKeyed_VerifyRequiresKey(t *testing.T) {
	path := tmpAuditPath(t)
	w, err := audit.OpenFileWriterKeyed(path, testMACKey)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, w, audit.EventGenesis, audit.EventVaultInit, audit.EventVaultUnlock)
	_ = w.Close()

	if err := audit.VerifyFileKeyed(path, testMACKey); err != nil {
		t.Fatalf("keyed verify should pass: %v", err)
	}
	if err := audit.VerifyFile(path); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("unkeyed verify of a keyed chain should fail with ErrChainBroken, got %v", err)
	}
	wrong := append([]byte(nil), testMACKey...)
	wrong[0] ^= 0xFF
	if err := audit.VerifyFileKeyed(path, wrong); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("wrong key should fail, got %v", err)
	}
}

// TestKeyed_TamperDetected: editing an entry without the key (the
// attacker's position) is caught, because they cannot recompute the
// HMAC.
func TestKeyed_TamperDetected(t *testing.T) {
	path := tmpAuditPath(t)
	w, err := audit.OpenFileWriterKeyed(path, testMACKey)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, w, audit.EventGenesis, audit.EventVaultInit, audit.EventVaultUnlock)
	_ = w.Close()

	// Attacker rewrites the actor of the second entry but cannot forge
	// its HMAC entry_hash.
	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("want >= 2 lines, got %d", len(lines))
	}
	var e map[string]any
	if err := json.Unmarshal(lines[1], &e); err != nil {
		t.Fatal(err)
	}
	e["actor"] = "attacker"
	tampered, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	lines[1] = tampered
	joined := append(bytes.Join(lines, []byte("\n")), '\n')
	if err := os.WriteFile(path, joined, 0o600); err != nil { // #nosec G703 -- test temp path
		t.Fatal(err)
	}

	if err := audit.VerifyFileKeyed(path, testMACKey); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("tamper must be detected, got %v", err)
	}
}

// TestKeyed_MixedChainVerifies: a chain that starts keyed (offensive
// write, has the vault) and continues unkeyed (harvest, no vault) still
// verifies with the key: keyed entries by HMAC, unkeyed by SHA-256.
func TestKeyed_MixedChainVerifies(t *testing.T) {
	path := tmpAuditPath(t)

	kw, err := audit.OpenFileWriterKeyed(path, testMACKey)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, kw, audit.EventGenesis, audit.EventVaultInit)
	_ = kw.Close()

	// A second process without the vault resumes the same file.
	uw, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, uw, audit.EventVaultUnlock)
	_ = uw.Close()

	if err := audit.VerifyFileKeyed(path, testMACKey); err != nil {
		t.Fatalf("mixed keyed+unkeyed chain should verify with the key: %v", err)
	}
}

// TestStrict_RejectsUnkeyedTail: an attacker who cannot forge the HMAC
// can still append (or rewrite) an UNKEYED tail that the lenient
// VerifyFileKeyed accepts by SHA-256; strict verification rejects it,
// closing the downgrade (PITF-108).
func TestStrict_RejectsUnkeyedTail(t *testing.T) {
	path := tmpAuditPath(t)

	kw, err := audit.OpenFileWriterKeyed(path, testMACKey)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, kw, audit.EventGenesis, audit.EventVaultInit)
	_ = kw.Close()

	// The attacker's position: no vault key, so they resume the chain
	// and append an unkeyed entry whose prev_hash links correctly.
	uw, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, uw, audit.EventVaultUnlock)
	_ = uw.Close()

	// Lenient mode accepts the downgraded tail.
	if err := audit.VerifyFileKeyed(path, testMACKey); err != nil {
		t.Fatalf("lenient verify should pass on a mixed chain: %v", err)
	}
	// Strict mode catches it.
	if err := audit.VerifyFileKeyedStrict(path, testMACKey); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("strict verify must reject the unkeyed tail, got %v", err)
	}
}

// TestStrict_FullyKeyedPasses: a chain whose every entry is keyed
// verifies under strict mode.
func TestStrict_FullyKeyedPasses(t *testing.T) {
	path := tmpAuditPath(t)
	w, err := audit.OpenFileWriterKeyed(path, testMACKey)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, w, audit.EventGenesis, audit.EventVaultInit, audit.EventVaultUnlock)
	_ = w.Close()

	if err := audit.VerifyFileKeyedStrict(path, testMACKey); err != nil {
		t.Fatalf("strict verify of a fully keyed chain should pass: %v", err)
	}
}

// TestStrict_RequiresKey: strict verification needs the vault key.
func TestStrict_RequiresKey(t *testing.T) {
	path := tmpAuditPath(t)
	w, err := audit.OpenFileWriterKeyed(path, testMACKey)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, w, audit.EventGenesis)
	_ = w.Close()

	if err := audit.VerifyFileKeyedStrict(path, nil); err == nil {
		t.Fatal("strict verify without a key must error")
	}
}
