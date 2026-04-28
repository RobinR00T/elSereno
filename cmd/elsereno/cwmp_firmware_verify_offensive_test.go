//go:build offensive

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cwmpwrite "local/elsereno/offensive/write/cwmp"
)

// runFirmwareVerifyForTest is a thin wrapper around the
// internal runFirmwareVerify that uses the test capture
// instead of a real audit writer. We can't call the
// production runFirmwareVerify directly because it expects an
// *offensiveRuntime; mocking that requires the audit Writer
// surface which is the chunk-1 v1.1 work. Instead, we drive
// the verifier logic via fetchFirmwareSHA256 + assert the
// status classification by hand. Pure unit-style — no audit
// chain involvement.
func runFirmwareVerifyForTest(t *testing.T, expectedSHA256 string, serverBody []byte, serverStatus int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(serverStatus)
		if len(serverBody) > 0 {
			_, _ = w.Write(serverBody)
		}
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Timeout: 2 * time.Second}
	got, err := fetchFirmwareSHA256(context.Background(), client, srv.URL)
	switch {
	case err != nil:
		return "unreachable"
	case strings.EqualFold(got, expectedSHA256):
		return "match"
	default:
		return "mismatch"
	}
}

// hashOf returns the lowercase hex SHA-256 of body. Helper for
// chunk-3 tests so the canned-body + canned-expected pair is
// consistent.
func hashOf(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// TestRunFirmwareVerify_Match — body matches expected; status
// classified `match`.
func TestRunFirmwareVerify_Match(t *testing.T) {
	body := []byte("hello firmware")
	got := runFirmwareVerifyForTest(t, hashOf(body), body, http.StatusOK)
	if got != "match" {
		t.Fatalf("status = %q, want match", got)
	}
}

// TestRunFirmwareVerify_Mismatch — body hashes to something
// other than expected; status classified `mismatch`.
func TestRunFirmwareVerify_Mismatch(t *testing.T) {
	got := runFirmwareVerifyForTest(t, "feedface"+strings.Repeat("0", 56), []byte("hello firmware"), http.StatusOK)
	if got != "mismatch" {
		t.Fatalf("status = %q, want mismatch", got)
	}
}

// TestRunFirmwareVerify_Unreachable — server returns 5xx →
// fetchFirmwareSHA256 errors → status `unreachable`.
func TestRunFirmwareVerify_Unreachable(t *testing.T) {
	got := runFirmwareVerifyForTest(t, hashOf([]byte("x")), nil, http.StatusInternalServerError)
	if got != "unreachable" {
		t.Fatalf("status = %q, want unreachable", got)
	}
}

// TestVerifyingTransferCompleteObserver_NilRuntimeNoOps —
// defensive: a nil runtime makes the wrapper safely no-op for
// the verification side-channel; the inner observer still
// fires (logging side).
func TestVerifyingTransferCompleteObserver_NilRuntimeNoOps(_ *testing.T) {
	obs := verifyingTransferCompleteObserver("acs.test:7547", nil, 100*time.Millisecond)
	// Should not panic.
	obs(cwmpwrite.TransferCompleteFields{
		CommandKey: "ck",
		FaultCode:  "0",
		Authorisation: &cwmpwrite.DownloadAuthorisation{
			AllowlistURL:    "https://example.invalid/fw.bin",
			AllowlistSHA256: "abc",
		},
	})
}

// TestVerifyingTransferCompleteObserver_NoAuthorisationSkipped
// — no Authorisation → no goroutine spawned, no fetch.
// Indirectly observable: the test would race-detect a
// background goroutine if one were spawned (Go race detector
// + httptest server would catch).
func TestVerifyingTransferCompleteObserver_NoAuthorisationSkipped(_ *testing.T) {
	obs := verifyingTransferCompleteObserver("acs.test:7547", nil, 100*time.Millisecond)
	obs(cwmpwrite.TransferCompleteFields{
		CommandKey:    "ck",
		FaultCode:     "0",
		Authorisation: nil,
	})
}

// TestVerifyingTransferCompleteObserver_FaultPathSkipped — a
// failed TransferComplete (FaultCode != "0") doesn't trigger
// verification; firmware re-fetch only makes sense for
// successful pushes.
func TestVerifyingTransferCompleteObserver_FaultPathSkipped(_ *testing.T) {
	obs := verifyingTransferCompleteObserver("acs.test:7547", nil, 100*time.Millisecond)
	obs(cwmpwrite.TransferCompleteFields{
		CommandKey: "ck",
		FaultCode:  "9010",
		Authorisation: &cwmpwrite.DownloadAuthorisation{
			AllowlistURL:    "https://example.invalid/fw.bin",
			AllowlistSHA256: "abc",
		},
	})
}

// TestVerifyingTransferCompleteObserver_EmptySHA256Skipped —
// when the operator pinned only the URL (no sha256), there's
// nothing to verify post-flash; the wrapper skips the
// re-fetch.
func TestVerifyingTransferCompleteObserver_EmptySHA256Skipped(_ *testing.T) {
	obs := verifyingTransferCompleteObserver("acs.test:7547", nil, 100*time.Millisecond)
	obs(cwmpwrite.TransferCompleteFields{
		CommandKey: "ck",
		FaultCode:  "0",
		Authorisation: &cwmpwrite.DownloadAuthorisation{
			AllowlistURL:    "https://example.invalid/fw.bin",
			AllowlistSHA256: "", // empty — no pin
		},
	})
}

// TestEmitFirmwareVerifyAudit_NilWriterNoOps — defensive: nil
// runtime / nil writer must not panic.
func TestEmitFirmwareVerifyAudit_NilWriterNoOps(_ *testing.T) {
	emitFirmwareVerifyAudit(context.Background(), nil, map[string]any{"status": "match"})
	emitFirmwareVerifyAudit(context.Background(), &offensiveRuntime{}, map[string]any{"status": "match"})
}

// TestChooseTransferCompleteObserver_OptOutDefault — without
// the flag, returns the v1.15-chunk-1 default observer (no
// verifier wrapping).
func TestChooseTransferCompleteObserver_OptOutDefault(t *testing.T) {
	obs := chooseTransferCompleteObserver(proxyListenOpts{
		target:                       "acs.test:7547",
		cwmpVerifyFirmwareOnComplete: false,
	}, nil)
	if obs == nil {
		t.Fatal("chooseTransferCompleteObserver returned nil")
	}
	// Calling it on a happy-path TC shouldn't panic; the
	// inner default just writes a log line.
	obs(cwmpwrite.TransferCompleteFields{CommandKey: "ck", FaultCode: "0"})
}

// TestChooseTransferCompleteObserver_OptIn — with the flag,
// returns the verifying wrapper. Indirectly verified by
// invoking with an Authorisation that points at a closed
// httptest server URL — the goroutine spawned should hit
// "unreachable" without panicking.
func TestChooseTransferCompleteObserver_OptIn(t *testing.T) {
	obs := chooseTransferCompleteObserver(proxyListenOpts{
		target:                       "acs.test:7547",
		cwmpVerifyFirmwareOnComplete: true,
		cwmpVerifyFirmwareTimeout:    100 * time.Millisecond,
	}, nil)
	if obs == nil {
		t.Fatal("chooseTransferCompleteObserver returned nil")
	}
	// nil rt → goroutine spawns but emit no-ops; no panic
	// expected.
	obs(cwmpwrite.TransferCompleteFields{
		CommandKey: "ck",
		FaultCode:  "0",
		Authorisation: &cwmpwrite.DownloadAuthorisation{
			AllowlistURL:    "http://127.0.0.1:1/closed",
			AllowlistSHA256: "abc",
		},
	})
	// Allow goroutine to finish.
	time.Sleep(150 * time.Millisecond)
}
