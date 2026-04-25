//go:build offensive

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVerifyCWMPFirmwareURLs_HappyPath — server returns body
// whose SHA-256 matches the operator-supplied expected hash;
// result is "match" + no failure.
func TestVerifyCWMPFirmwareURLs_HappyPath(t *testing.T) {
	body := []byte("firmware-image-bytes-v1.2.3")
	want := sha256Hex(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	entries := []proxyCWMPFirmware{
		{URL: srv.URL + "/router-1.2.3.bin", SHA256: want},
	}
	results, anyFail := verifyCWMPFirmwareURLs(context.Background(), entries, 5*time.Second)
	if anyFail {
		t.Fatalf("expected no failures, got %+v", results)
	}
	if len(results) != 1 || results[0].Status != "match" {
		t.Errorf("results = %+v, want one match", results)
	}
}

// TestVerifyCWMPFirmwareURLs_Mismatch — server returns body
// whose SHA-256 doesn't match the operator's expected hash;
// status mismatch + anyFail=true.
func TestVerifyCWMPFirmwareURLs_Mismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("a different image"))
	}))
	defer srv.Close()

	entries := []proxyCWMPFirmware{
		{URL: srv.URL + "/swapped.bin", SHA256: strings.Repeat("0", 64)},
	}
	results, anyFail := verifyCWMPFirmwareURLs(context.Background(), entries, 5*time.Second)
	if !anyFail {
		t.Fatalf("expected failure, got %+v", results)
	}
	if results[0].Status != "mismatch" {
		t.Errorf("results[0].Status = %q, want mismatch", results[0].Status)
	}
	if !strings.Contains(results[0].Detail, "expected") {
		t.Errorf("expected detail to mention expected vs got: %s", results[0].Detail)
	}
}

// TestVerifyCWMPFirmwareURLs_NoSHA256Skipped — entries without
// a sha256: get a "skipped" status but don't count as a failure.
func TestVerifyCWMPFirmwareURLs_NoSHA256Skipped(t *testing.T) {
	entries := []proxyCWMPFirmware{
		{URL: "https://acs.example.com/no-hash.bin"},
	}
	results, anyFail := verifyCWMPFirmwareURLs(context.Background(), entries, 5*time.Second)
	if anyFail {
		t.Fatalf("missing-hash entries should not count as failures: %+v", results)
	}
	if results[0].Status != "skipped" {
		t.Errorf("status = %q, want skipped", results[0].Status)
	}
}

// TestVerifyCWMPFirmwareURLs_500SurfacesAsError — server 500
// surfaces as error status + counts as failure.
func TestVerifyCWMPFirmwareURLs_500SurfacesAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	entries := []proxyCWMPFirmware{
		{URL: srv.URL + "/cant-fetch.bin", SHA256: strings.Repeat("0", 64)},
	}
	results, anyFail := verifyCWMPFirmwareURLs(context.Background(), entries, 5*time.Second)
	if !anyFail {
		t.Fatalf("expected failure on 500, got %+v", results)
	}
	if results[0].Status != "error" {
		t.Errorf("status = %q, want error", results[0].Status)
	}
}

// TestNewWriteCWMPVerifyFirmwareCmd_AllowFileMissing — operator
// fails to pass --allow-file → exit usage.
func TestNewWriteCWMPVerifyFirmwareCmd_AllowFileMissing(t *testing.T) {
	cmd := newWriteCWMPVerifyFirmwareCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --allow-file required error")
	}
}

// TestNewWriteCWMPVerifyFirmwareCmd_E2E_Match — full CLI run:
// emit a YAML allow-file via buildAllowFileCWMP, then invoke
// verify-firmware against an httptest server. End-to-end.
func TestNewWriteCWMPVerifyFirmwareCmd_E2E_Match(t *testing.T) {
	body := []byte("firmware-bytes")
	hash := sha256Hex(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "allow.yaml")

	// Build the YAML through the same emitter the operator
	// would use.
	af := buildAllowFileCWMP("acs.example.com:7547",
		[]string{"Download"}, nil,
		[]string{"url=" + srv.URL + ";sha256=" + hash})
	yamlBuf := bytes.Buffer{}
	helper := helperCmd(&yamlBuf)
	if err := emitAllowFile(helper, yamlPath, af); err != nil {
		t.Fatalf("emit: %v", err)
	}

	cmd := newWriteCWMPVerifyFirmwareCmd()
	cmd.SilenceUsage = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--allow-file", yamlPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "✓ MATCH") {
		t.Errorf("expected ✓ MATCH line, got:\n%s", out.String())
	}
}

// TestNewWriteCWMPVerifyFirmwareCmd_E2E_Mismatch — same flow
// but with the wrong expected hash; CLI returns a non-nil error
// and writes a MISMATCH line.
func TestNewWriteCWMPVerifyFirmwareCmd_E2E_Mismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("malicious-image"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "allow.yaml")

	af := buildAllowFileCWMP("acs.example.com:7547",
		[]string{"Download"}, nil,
		[]string{"url=" + srv.URL + ";sha256=" + strings.Repeat("0", 64)})
	yamlBuf := bytes.Buffer{}
	helper := helperCmd(&yamlBuf)
	if err := emitAllowFile(helper, yamlPath, af); err != nil {
		t.Fatalf("emit: %v", err)
	}

	cmd := newWriteCWMPVerifyFirmwareCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--allow-file", yamlPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(out.String(), "✗ MISMATCH") {
		t.Errorf("expected ✗ MISMATCH line, got:\n%s", out.String())
	}
}

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Touched by tests above — silence "imported and not used" if
// we ever drop one.
var _ = os.Getenv
