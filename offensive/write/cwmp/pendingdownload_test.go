//go:build offensive

package cwmp_test

import (
	"strings"
	"testing"

	cwmpwrite "local/elsereno/offensive/write/cwmp"
)

// TestExtractDownloadCommandKey_HappyPath — typical Download
// SOAP body with all fields → returns CommandKey verbatim.
func TestExtractDownloadCommandKey_HappyPath(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:cwmp="urn:dslforum-org:cwmp-1-2">
  <soap-env:Body>
    <cwmp:Download>
      <CommandKey>firmware-rollout-q2</CommandKey>
      <FileType>1 Firmware Upgrade Image</FileType>
      <URL>https://acs.example/fw.bin</URL>
    </cwmp:Download>
  </soap-env:Body>
</soap-env:Envelope>`)
	got := cwmpwrite.ExtractDownloadCommandKeyForTest(body)
	if got != "firmware-rollout-q2" {
		t.Errorf("ExtractDownloadCommandKey = %q, want %q", got, "firmware-rollout-q2")
	}
}

// TestExtractDownloadCommandKey_Missing — older or non-
// conformant ACS sends Download without CommandKey → returns "".
func TestExtractDownloadCommandKey_Missing(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:cwmp="urn:dslforum-org:cwmp-1-2">
  <soap-env:Body>
    <cwmp:Download>
      <FileType>1 Firmware Upgrade Image</FileType>
      <URL>https://acs.example/fw.bin</URL>
    </cwmp:Download>
  </soap-env:Body>
</soap-env:Envelope>`)
	got := cwmpwrite.ExtractDownloadCommandKeyForTest(body)
	if got != "" {
		t.Errorf("ExtractDownloadCommandKey = %q, want empty for absent <CommandKey>", got)
	}
}

// TestExtractDownloadCommandKey_NotADownload — a non-Download
// SOAP body shouldn't pick up a CommandKey from a different RPC.
// Tests the streaming decoder's "must be inside <Download>"
// guard.
func TestExtractDownloadCommandKey_NotADownload(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:cwmp="urn:dslforum-org:cwmp-1-2">
  <soap-env:Body>
    <cwmp:Reboot>
      <CommandKey>some-other-rpc</CommandKey>
    </cwmp:Reboot>
  </soap-env:Body>
</soap-env:Envelope>`)
	got := cwmpwrite.ExtractDownloadCommandKeyForTest(body)
	if got != "" {
		t.Errorf("ExtractDownloadCommandKey = %q, want empty (CommandKey was inside <Reboot>, not <Download>)", got)
	}
}

// TestPendingDownloadCap_EvictsOldest — exercise the FIFO
// eviction when PendingDownloadCap is reached. Uses the
// exported test-only RecordDownload + ResolveDownload entry
// points so we don't need a full proxy session.
func TestPendingDownloadCap_EvictsOldest(t *testing.T) {
	h := &cwmpwrite.WriteGatedHandler{
		Target:             "acs.test:7547",
		PendingDownloadCap: 3,
	}
	keys := []string{"a", "b", "c", "d"} // 4 inserts, cap=3 → "a" evicted
	for _, k := range keys {
		body := []byte(`<cwmp:Download>` +
			`<CommandKey>` + k + `</CommandKey>` +
			`<URL>https://acs.example/fw-` + k + `.bin</URL>` +
			`</cwmp:Download>`)
		cwmpwrite.RecordDownloadForTest(h, body)
	}

	// "a" should be evicted (oldest).
	if _, ok := cwmpwrite.ResolveDownloadForTest(h, "a"); ok {
		t.Errorf(`resolve("a") returned ok=true; want false (evicted)`)
	}
	// "b" / "c" / "d" should all still resolve (one-shot).
	for _, k := range []string{"b", "c", "d"} {
		auth, ok := cwmpwrite.ResolveDownloadForTest(h, k)
		if !ok {
			t.Errorf(`resolve(%q) returned ok=false; want true`, k)
			continue
		}
		if auth.CommandKey != k {
			t.Errorf(`resolve(%q): CommandKey = %q, want %q`, k, auth.CommandKey, k)
		}
		if !strings.Contains(auth.DownloadURL, "fw-"+k+".bin") {
			t.Errorf(`resolve(%q): DownloadURL = %q, missing fw-%s.bin`, k, auth.DownloadURL, k)
		}
	}
}

// TestRecordDownload_DuplicateCommandKeyReplaces — when the
// operator re-uses a CommandKey within the same session (rare
// but legal), the latest record replaces the prior one in
// place; the FIFO order tracker doesn't double-count it.
func TestRecordDownload_DuplicateCommandKeyReplaces(t *testing.T) {
	h := &cwmpwrite.WriteGatedHandler{
		Target:             "acs.test:7547",
		PendingDownloadCap: 2,
	}
	body1 := []byte(`<cwmp:Download><CommandKey>k</CommandKey><URL>https://acs.example/fw1.bin</URL></cwmp:Download>`)
	body2 := []byte(`<cwmp:Download><CommandKey>k</CommandKey><URL>https://acs.example/fw2.bin</URL></cwmp:Download>`)
	body3 := []byte(`<cwmp:Download><CommandKey>other</CommandKey><URL>https://acs.example/fw3.bin</URL></cwmp:Download>`)
	cwmpwrite.RecordDownloadForTest(h, body1)
	cwmpwrite.RecordDownloadForTest(h, body2)
	cwmpwrite.RecordDownloadForTest(h, body3)

	// Both keys should still be resolvable (no eviction — cap 2,
	// two distinct keys — duplicate "k" replaced the slot, didn't
	// double-fill).
	gotK, ok := cwmpwrite.ResolveDownloadForTest(h, "k")
	if !ok {
		t.Fatal(`resolve("k") returned ok=false; want true (latest record kept)`)
	}
	if !strings.Contains(gotK.DownloadURL, "fw2.bin") {
		t.Errorf("DownloadURL after duplicate = %q, want contains fw2.bin (latest record)", gotK.DownloadURL)
	}
	if _, ok := cwmpwrite.ResolveDownloadForTest(h, "other"); !ok {
		t.Error(`resolve("other") returned ok=false; want true (cap 2, two distinct keys; duplicate shouldn't have caused eviction)`)
	}
}

// TestRecordDownload_SkipsEmptyCommandKey — a Download with no
// CommandKey isn't recorded (we'd have nothing to correlate
// later). The Download still forwards upstream — that's a
// separate path.
func TestRecordDownload_SkipsEmptyCommandKey(t *testing.T) {
	h := &cwmpwrite.WriteGatedHandler{Target: "acs.test:7547"}
	body := []byte(`<cwmp:Download><URL>https://acs.example/fw.bin</URL></cwmp:Download>`)
	cwmpwrite.RecordDownloadForTest(h, body)
	if _, ok := cwmpwrite.ResolveDownloadForTest(h, ""); ok {
		t.Error(`resolve("") returned ok=true; want false (empty key never resolves)`)
	}
}
