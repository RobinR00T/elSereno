package s7_test

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/s7"
	"local/elsereno/internal/protocols/s7/wire"
)

// Real captured FULL TPKT responses (ITI/ICS-Security-Tools
// s7comm_reading_plc_status.pcap): COTP Connection Confirm, Setup
// Communication AckData, and the SZL 0x0132/4 protection response
// (key=1, param=0, real=1, bart_sch=RUN_P).
const (
	realCOTPConfirm = "0300001611d0000f000300c0010ac1020100c2020102"
	realSetupRespTP = "0300001b02f080320300000200000800000000f0000001000100f0"
	realSZLRespTP   = "0300005102f080320700000300000c0034000112081284010100000000ff090030" +
		"013200040028000100040001000000010002000000005656bc04a3d58401d6b2" +
		"02000000000000000000000000000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serve replays canned full-TPKT responses in order, consuming one client
// TPKT before each reply so the exchange stays in sync.
func serve(t *testing.T, conn net.Conn, responses [][]byte) {
	t.Helper()
	for _, resp := range responses {
		if _, err := wire.ReadTPKT(conn); err != nil {
			return
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

func TestProbeProtection_ExposedRealBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	go serve(t, serverConn, [][]byte{
		mustHex(t, realCOTPConfirm),
		mustHex(t, realSetupRespTP),
		mustHex(t, realSZLRespTP),
	})

	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := s7.ProbeProtection(context.Background(), clientConn)
	if err != nil {
		t.Fatalf("ProbeProtection: %v", err)
	}
	if !res.IsS7 || !res.SetupOK || !res.ProtectionRead {
		t.Fatalf("handshake incomplete: %+v", res)
	}
	if res.Record.RealLevel != 1 || res.Record.ModeSelector != wire.ModeSelectorRUNP {
		t.Errorf("record = %+v, want RealLevel 1 / ModeSelector RUN-P", res.Record)
	}
	if !res.Exposed {
		t.Error("Exposed = false; effective level 1 should be flagged as exposed")
	}
}

func TestProbeProtection_NotS7(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	// Reply to the COTP CR with a COTP Disconnect Request (not a Confirm).
	disconnect := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0x80, 0x00, 0x00, 0x00, 0x0f, 0x00}
	go serve(t, serverConn, [][]byte{disconnect})

	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := s7.ProbeProtection(context.Background(), clientConn)
	if err != nil {
		t.Fatalf("ProbeProtection: %v", err)
	}
	if res.IsS7 || res.SetupOK || res.ProtectionRead {
		t.Fatalf("a non-Confirm reply must leave everything false: %+v", res)
	}
}
