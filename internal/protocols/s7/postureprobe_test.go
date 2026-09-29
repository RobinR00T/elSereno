package s7_test

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/s7"
	"local/elsereno/internal/protocols/s7/wire"
)

// TestProbePosture_RealBytes replays the full posture flow over net.Pipe
// using the real captured responses: COTP Confirm, Setup, SZL 0x0011,
// SZL 0x001C, SZL 0x0132/4. It exercises one handshake feeding both the
// identity and protection reads.
func TestProbePosture_RealBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	go serve(t, serverConn, [][]byte{
		mustHex(t, realCOTPConfirm),
		mustHex(t, realSetupRespTP),
		mustHex(t, realModuleIdentRespTP),
		mustHex(t, realCompIdentRespTP),
		mustHex(t, realSZLRespTP),
	})

	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := s7.ProbePosture(context.Background(), clientConn)
	if err != nil {
		t.Fatalf("ProbePosture: %v", err)
	}
	if !res.IsS7 || !res.SetupOK {
		t.Fatalf("handshake incomplete: %+v", res)
	}
	if res.OrderNumber != "6ES7 151-8AB01-0AB0" || res.Firmware != "V3.2.6" {
		t.Errorf("identity = %q / %q, want order 6ES7 151-8AB01-0AB0 / fw V3.2.6", res.OrderNumber, res.Firmware)
	}
	if res.SerialNumber != "S C-C6TW74882012" {
		t.Errorf("serial = %q, want \"S C-C6TW74882012\"", res.SerialNumber)
	}
	if !res.ProtectionRead || res.Protection.RealLevel != 1 || res.Protection.ModeSelector != wire.ModeSelectorRUNP {
		t.Errorf("protection = %+v (read=%v), want RealLevel 1 / RUN-P", res.Protection, res.ProtectionRead)
	}
	if !res.Exposed {
		t.Error("Exposed = false; effective level 1 should be flagged")
	}
}
