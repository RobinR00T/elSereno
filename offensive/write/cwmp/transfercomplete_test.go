//go:build offensive

package cwmp_test

import (
	"context"
	"net"
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
