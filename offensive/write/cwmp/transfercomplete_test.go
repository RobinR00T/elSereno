//go:build offensive

package cwmp_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
)

// soapTransferComplete builds a TransferComplete SOAP body.
// FaultCode "0" means success; any other code is a CPE-reported
// failure.
func soapTransferComplete(commandKey, faultCode, faultString, startTime, completeTime string) string {
	return soapEnvelope(`<cwmp:TransferComplete>` +
		`<CommandKey>` + commandKey + `</CommandKey>` +
		`<FaultStruct>` +
		`<FaultCode>` + faultCode + `</FaultCode>` +
		`<FaultString>` + faultString + `</FaultString>` +
		`</FaultStruct>` +
		`<StartTime>` + startTime + `</StartTime>` +
		`<CompleteTime>` + completeTime + `</CompleteTime>` +
		`</cwmp:TransferComplete>`)
}

// driveSessionWithObserver mirrors driveSession but also wires
// an OnTransferComplete observer + returns the captured fields
// slice (mutex-protected — the callback runs on the proxy
// goroutine).
func driveSessionWithObserver(t *testing.T) (net.Conn, *upstreamACS, func() []cwmpwrite.TransferCompleteFields) {
	t.Helper()
	target := "acs.test:7547"
	var (
		mu       sync.Mutex
		captured []cwmpwrite.TransferCompleteFields
	)
	h := &cwmpwrite.WriteGatedHandler{
		Target:  target,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, nil),
		},
		OnTransferComplete: func(f cwmpwrite.TransferCompleteFields) {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, f)
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientPipe, handlerClientSide := net.Pipe()
	handlerUpstreamSide, originSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = originSide.Close()
	})
	acs := &upstreamACS{}
	go acs.run(originSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	snapshot := func() []cwmpwrite.TransferCompleteFields {
		mu.Lock()
		defer mu.Unlock()
		out := make([]cwmpwrite.TransferCompleteFields, len(captured))
		copy(out, captured)
		return out
	}
	return clientPipe, acs, snapshot
}

// TestObserveTransferComplete_SuccessPath — CPE reports success
// (FaultCode "0"). Observer fires; gate forwards request
// unchanged to upstream; IsSuccess() returns true.
func TestObserveTransferComplete_SuccessPath(t *testing.T) {
	client, acs, snap := driveSessionWithObserver(t)
	body := soapTransferComplete(
		"firmware-push-2026-04-26",
		"0",
		"",
		"2026-04-26T15:00:00Z",
		"2026-04-26T15:05:00Z",
	)
	if _, err := client.Write([]byte(postRequest(body))); err != nil {
		t.Fatal(err)
	}
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	got := snap()
	if len(got) != 1 {
		t.Fatalf("observer got %d invocations, want 1", len(got))
	}
	f := got[0]
	if f.CommandKey != "firmware-push-2026-04-26" {
		t.Errorf("CommandKey = %q", f.CommandKey)
	}
	if !f.IsSuccess() {
		t.Errorf("IsSuccess() = false, want true (FaultCode=%q)", f.FaultCode)
	}
	if f.StartTime != "2026-04-26T15:00:00Z" {
		t.Errorf("StartTime = %q", f.StartTime)
	}
	if f.CompleteTime != "2026-04-26T15:05:00Z" {
		t.Errorf("CompleteTime = %q", f.CompleteTime)
	}
	if _, count := acs.seen(); count == 0 {
		t.Error("upstream ACS saw no request — observer must NOT swallow forwarding")
	}
}

// TestObserveTransferComplete_FaultPath — CPE reports failure.
func TestObserveTransferComplete_FaultPath(t *testing.T) {
	client, _, snap := driveSessionWithObserver(t)
	body := soapTransferComplete(
		"firmware-push-2026-04-26",
		"9010", // TR-069: download failure
		"Download failed: 404 Not Found",
		"2026-04-26T15:00:00Z",
		"2026-04-26T15:00:30Z",
	)
	_, _ = client.Write([]byte(postRequest(body)))
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	got := snap()
	if len(got) != 1 {
		t.Fatalf("observer got %d invocations, want 1", len(got))
	}
	f := got[0]
	if f.IsSuccess() {
		t.Errorf("IsSuccess() = true, want false for FaultCode %q", f.FaultCode)
	}
	if f.FaultCode != "9010" {
		t.Errorf("FaultCode = %q, want 9010", f.FaultCode)
	}
	if f.FaultString != "Download failed: 404 Not Found" {
		t.Errorf("FaultString = %q", f.FaultString)
	}
}

// TestObserveTransferComplete_NotInvokedForOtherRPCs — observer
// must fire ONLY for TransferComplete, not for other always-safe
// RPCs (Inform / Kicked / Fault / GetParameter*).
func TestObserveTransferComplete_NotInvokedForOtherRPCs(t *testing.T) {
	client, _, snap := driveSessionWithObserver(t)
	body := soapEnvelope(`<cwmp:Inform><DeviceId/><Event/><MaxEnvelopes>1</MaxEnvelopes></cwmp:Inform>`)
	_, _ = client.Write([]byte(postRequest(body)))
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)
	if len(snap()) != 0 {
		t.Errorf("observer fired for Inform — must only fire for TransferComplete")
	}
}

// TestObserveTransferComplete_NilObserverNoOps — when
// OnTransferComplete is nil, the gate forwards TransferComplete
// transparently without inspection. Regression guard.
func TestObserveTransferComplete_NilObserverNoOps(t *testing.T) {
	client, acs := driveSession(t, nil)
	body := soapTransferComplete("ck", "0", "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")
	_, _ = client.Write([]byte(postRequest(body)))
	_, _, _ = readHTTPResponseSummary(t, client)
	if _, count := acs.seen(); count == 0 {
		t.Error("upstream must receive TransferComplete even when no observer is set")
	}
}

// TestObserveTransferComplete_MissingCommandKey — older / non-
// conformant CPEs may send TransferComplete without a CommandKey.
// The parser tolerates that (empty string) + observer still
// fires.
func TestObserveTransferComplete_MissingCommandKey(t *testing.T) {
	client, _, snap := driveSessionWithObserver(t)
	body := soapEnvelope(`<cwmp:TransferComplete>` +
		`<FaultStruct><FaultCode>0</FaultCode><FaultString></FaultString></FaultStruct>` +
		`<StartTime>2026-04-26T15:00:00Z</StartTime>` +
		`<CompleteTime>2026-04-26T15:05:00Z</CompleteTime>` +
		`</cwmp:TransferComplete>`)
	_, _ = client.Write([]byte(postRequest(body)))
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)
	got := snap()
	if len(got) != 1 {
		t.Fatalf("observer got %d invocations, want 1", len(got))
	}
	if got[0].CommandKey != "" {
		t.Errorf("CommandKey = %q, want empty for missing element", got[0].CommandKey)
	}
	if !got[0].IsSuccess() {
		t.Errorf("IsSuccess() = false, want true")
	}
}

// TestTransferCompleteFields_IsSuccess — pin the FaultCode
// semantics: exactly "0" → success, anything else → fault.
// Whitespace + leading zeros are NOT massaged at this layer
// (parser already TrimSpace'd).
func TestTransferCompleteFields_IsSuccess(t *testing.T) {
	cases := map[string]bool{
		"0":    true,
		"":     false,
		"9010": false,
		"9012": false, // checksum mismatch
		"00":   false, // leading zeros are NOT "0" — be strict
	}
	for code, want := range cases {
		t.Run(code, func(t *testing.T) {
			f := cwmpwrite.TransferCompleteFields{FaultCode: code}
			if f.IsSuccess() != want {
				t.Errorf("IsSuccess() for %q = %v, want %v", code, f.IsSuccess(), want)
			}
		})
	}
}

// TestTransferCompleteFields_Outcome — pin the v1.16 chunk-1
// outcome classifier semantics. Crosses (IsSuccess, hasAuth) ×
// the four resulting labels.
func TestTransferCompleteFields_Outcome(t *testing.T) {
	auth := &cwmpwrite.DownloadAuthorisation{CommandKey: "ck"}
	cases := []struct {
		name    string
		fields  cwmpwrite.TransferCompleteFields
		outcome string
	}{
		{
			name:    "succeeded_with_auth",
			fields:  cwmpwrite.TransferCompleteFields{FaultCode: "0", Authorisation: auth},
			outcome: "succeeded",
		},
		{
			name:    "failed_with_auth",
			fields:  cwmpwrite.TransferCompleteFields{FaultCode: "9010", Authorisation: auth},
			outcome: "failed",
		},
		{
			name:    "orphan_complete_no_auth",
			fields:  cwmpwrite.TransferCompleteFields{FaultCode: "0", Authorisation: nil},
			outcome: "orphan_complete",
		},
		{
			name:    "orphan_fault_no_auth",
			fields:  cwmpwrite.TransferCompleteFields{FaultCode: "9012", Authorisation: nil},
			outcome: "orphan_fault",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.fields.Outcome(); got != c.outcome {
				t.Errorf("Outcome() = %q, want %q", got, c.outcome)
			}
		})
	}
}

// soapDownloadWithKey builds a Download SOAP envelope with the
// given CommandKey + URL. v1.16 chunk 1 helper.
func soapDownloadWithKey(commandKey, url string) string {
	return soapEnvelope(`<cwmp:Download>` +
		`<CommandKey>` + commandKey + `</CommandKey>` +
		`<FileType>1 Firmware Upgrade Image</FileType>` +
		`<URL>` + url + `</URL>` +
		`<FileSize>0</FileSize>` +
		`<DelaySeconds>0</DelaySeconds>` +
		`</cwmp:Download>`)
}

// driveSessionWithFirmwareAndObserver wires both an
// AllowedFirmware allowlist (so Download is gate-allowed) AND
// an OnTransferComplete observer, then drives the proxy. The
// Download RPC is added to Allowed so the RPC gate doesn't
// refuse it. Returns the client conn + observer snapshot fn.
func driveSessionWithFirmwareAndObserver(t *testing.T, fws []cwmpwrite.AllowedFirmware) (net.Conn, func() []cwmpwrite.TransferCompleteFields) {
	t.Helper()
	target := "acs.test:7547"
	allowed := []cwmpwrite.AllowedRPC{{Name: "Download"}}

	// Token must be derived from the same SessionMutationWith*
	// shape the handler uses at Authorise time.
	mut := cwmpwrite.SessionMutationWithFirmware(target, allowed, nil, fws)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatalf("expected-token: %v", err)
	}

	var (
		mu       sync.Mutex
		captured []cwmpwrite.TransferCompleteFields
	)
	h := &cwmpwrite.WriteGatedHandler{
		Target:          target,
		Allowed:         allowed,
		AllowedFirmware: fws,
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tok,
		},
		OnTransferComplete: func(f cwmpwrite.TransferCompleteFields) {
			mu.Lock()
			defer mu.Unlock()
			captured = append(captured, f)
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientPipe, handlerClientSide := net.Pipe()
	handlerUpstreamSide, originSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = originSide.Close()
	})
	acs := &upstreamACS{}
	go acs.run(originSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	snapshot := func() []cwmpwrite.TransferCompleteFields {
		mu.Lock()
		defer mu.Unlock()
		out := make([]cwmpwrite.TransferCompleteFields, len(captured))
		copy(out, captured)
		return out
	}
	return clientPipe, snapshot
}

// TestObserveTransferComplete_ResolvesAuthorisationFromPriorDownload
// — drive a Download → drive a TransferComplete with the same
// CommandKey → observer sees fields.Authorisation populated
// with the canonical URL + SHA256 from the AllowedFirmware
// entry that authorised the Download. v1.16 chunk 1.
func TestObserveTransferComplete_ResolvesAuthorisationFromPriorDownload(t *testing.T) {
	url := "https://acs.example.com/firmware/router-1.2.3.bin"
	wantSHA := "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	fws := []cwmpwrite.AllowedFirmware{{URL: url, SHA256: wantSHA}}
	client, snap := driveSessionWithFirmwareAndObserver(t, fws)

	// 1. Authorised Download.
	if _, err := client.Write([]byte(postRequest(soapDownloadWithKey("fw-update-42", url)))); err != nil {
		t.Fatal(err)
	}
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	// 2. CPE reports TransferComplete success on same key.
	if _, err := client.Write([]byte(postRequest(soapTransferComplete(
		"fw-update-42", "0", "",
		"2026-04-26T15:00:00Z", "2026-04-26T15:05:00Z",
	)))); err != nil {
		t.Fatal(err)
	}
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	got := snap()
	if len(got) != 1 {
		t.Fatalf("observer got %d invocations, want 1", len(got))
	}
	f := got[0]
	if f.Authorisation == nil {
		t.Fatal("Authorisation = nil; want populated DownloadAuthorisation for matched CommandKey")
	}
	if f.Authorisation.CommandKey != "fw-update-42" {
		t.Errorf("Authorisation.CommandKey = %q", f.Authorisation.CommandKey)
	}
	if f.Authorisation.DownloadURL != url {
		t.Errorf("Authorisation.DownloadURL = %q, want %q", f.Authorisation.DownloadURL, url)
	}
	if f.Authorisation.AllowlistURL != url {
		t.Errorf("Authorisation.AllowlistURL = %q, want %q", f.Authorisation.AllowlistURL, url)
	}
	if f.Authorisation.AllowlistSHA256 != wantSHA {
		t.Errorf("Authorisation.AllowlistSHA256 = %q, want %q", f.Authorisation.AllowlistSHA256, wantSHA)
	}
	if f.Outcome() != "succeeded" {
		t.Errorf("Outcome() = %q, want succeeded", f.Outcome())
	}
}

// TestObserveTransferComplete_OrphanCompleteHasNoAuthorisation
// — when the CPE reports TransferComplete for a CommandKey we
// never authorised, observer fields.Authorisation is nil and
// Outcome() returns "orphan_complete". Suspicious from an
// operator perspective. v1.16 chunk 1.
func TestObserveTransferComplete_OrphanCompleteHasNoAuthorisation(t *testing.T) {
	client, _, snap := driveSessionWithObserver(t)
	if _, err := client.Write([]byte(postRequest(soapTransferComplete(
		"unknown-key-from-other-acs", "0", "",
		"2026-04-26T15:00:00Z", "2026-04-26T15:05:00Z",
	)))); err != nil {
		t.Fatal(err)
	}
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	got := snap()
	if len(got) != 1 {
		t.Fatalf("observer got %d invocations, want 1", len(got))
	}
	if got[0].Authorisation != nil {
		t.Errorf("Authorisation = %#v; want nil for orphan complete", got[0].Authorisation)
	}
	if got[0].Outcome() != "orphan_complete" {
		t.Errorf("Outcome() = %q, want orphan_complete", got[0].Outcome())
	}
}

// TestObserveTransferComplete_FaultPathStillResolves — the gate
// resolves the Authorisation regardless of FaultCode. Operator
// authorised Download, CPE reports failure (e.g. 9010). The
// observer sees Authorisation populated AND IsSuccess()=false.
// v1.16 chunk 1.
func TestObserveTransferComplete_FaultPathStillResolves(t *testing.T) {
	url := "https://acs.example.com/firmware/router-1.2.3.bin"
	fws := []cwmpwrite.AllowedFirmware{{URL: url, SHA256: "deadbeef" + strings.Repeat("0", 56)}}
	client, snap := driveSessionWithFirmwareAndObserver(t, fws)

	if _, err := client.Write([]byte(postRequest(soapDownloadWithKey("fw-fail-1", url)))); err != nil {
		t.Fatal(err)
	}
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	if _, err := client.Write([]byte(postRequest(soapTransferComplete(
		"fw-fail-1", "9010", "Download failed: 404 Not Found",
		"2026-04-26T15:00:00Z", "2026-04-26T15:00:30Z",
	)))); err != nil {
		t.Fatal(err)
	}
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	got := snap()
	if len(got) != 1 {
		t.Fatalf("observer got %d invocations, want 1", len(got))
	}
	f := got[0]
	if f.IsSuccess() {
		t.Errorf("IsSuccess() = true, want false for FaultCode=9010")
	}
	if f.Authorisation == nil {
		t.Fatal("Authorisation = nil; even on fault path the gate must resolve the prior Download")
	}
	if f.Authorisation.CommandKey != "fw-fail-1" {
		t.Errorf("Authorisation.CommandKey = %q", f.Authorisation.CommandKey)
	}
	if f.Outcome() != "failed" {
		t.Errorf("Outcome() = %q, want failed", f.Outcome())
	}
}

// TestObserveTransferComplete_ResolveIsOneShot — once
// resolveDownload pops a CommandKey, a second TransferComplete
// with the same key gets nil Authorisation. Defensive test:
// duplicate / replayed TransferComplete shouldn't double-
// surface the same authorisation. v1.16 chunk 1.
func TestObserveTransferComplete_ResolveIsOneShot(t *testing.T) {
	url := "https://acs.example.com/firmware/router-1.2.3.bin"
	fws := []cwmpwrite.AllowedFirmware{{URL: url}}
	client, snap := driveSessionWithFirmwareAndObserver(t, fws)

	if _, err := client.Write([]byte(postRequest(soapDownloadWithKey("ck-once", url)))); err != nil {
		t.Fatal(err)
	}
	_, _, _ = readHTTPResponseSummary(t, client)
	time.Sleep(50 * time.Millisecond)

	for i := 0; i < 2; i++ {
		if _, err := client.Write([]byte(postRequest(soapTransferComplete(
			"ck-once", "0", "",
			"2026-04-26T15:00:00Z", "2026-04-26T15:05:00Z",
		)))); err != nil {
			t.Fatal(err)
		}
		_, _, _ = readHTTPResponseSummary(t, client)
		time.Sleep(50 * time.Millisecond)
	}

	got := snap()
	if len(got) != 2 {
		t.Fatalf("observer got %d invocations, want 2 (one per TransferComplete)", len(got))
	}
	if got[0].Authorisation == nil {
		t.Error("first TransferComplete: Authorisation = nil; want populated")
	}
	if got[1].Authorisation != nil {
		t.Errorf("second TransferComplete: Authorisation = %#v; want nil after one-shot resolve", got[1].Authorisation)
	}
	if got[1].Outcome() != "orphan_complete" {
		t.Errorf("second TransferComplete: Outcome() = %q, want orphan_complete", got[1].Outcome())
	}
}
