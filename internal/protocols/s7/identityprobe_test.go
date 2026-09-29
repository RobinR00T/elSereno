package s7_test

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/s7"
)

// Real captured FULL TPKT identity responses (ITI/ICS-Security-Tools
// s7comm_reading_plc_status.pcap): SZL 0x0011 (module) and SZL 0x001C
// (component). CPU: IM151-8 PN/DP CPU, 6ES7 151-8AB01-0AB0, V3.2.6,
// serial "S C-C6TW74882012".
const (
	realModuleIdentRespTP = "0300009902f080320700001100000c007c000112081284010200000000ff09007800110000001c0004000136455337203135312d38414230312d304142302000c000030001000636455337203135312d38414230312d304142302000c0000300010007202020202020202020202020202020202020202000c0560302060081426f6f74204c6f61646572202020202020202020000041200909"
	realCompIdentRespTP   = "030000f702f080320700001400000c00da000112081284010206010000ff0900d6001c00000022000a0001494d3135312d382d4350550000000000000000000000000000000000000000000002494d3135312d3820504e2f4450204350550000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000044f726967696e616c205369656d656e732045717569706d656e7400000000000000055320432d433654573734383832303132000000000000000000000000000000000007494d3135312d3820504e2f4450204350550000000000000000000000000000000008"
)

func TestProbeIdentity_RealBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	go serve(t, serverConn, [][]byte{
		mustHex(t, realCOTPConfirm),
		mustHex(t, realSetupRespTP),
		mustHex(t, realModuleIdentRespTP),
		mustHex(t, realCompIdentRespTP),
	})

	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := s7.ProbeIdentity(context.Background(), clientConn)
	if err != nil {
		t.Fatalf("ProbeIdentity: %v", err)
	}
	if !res.IsS7 || !res.SetupOK {
		t.Fatalf("handshake incomplete: %+v", res)
	}
	if res.OrderNumber != "6ES7 151-8AB01-0AB0" {
		t.Errorf("OrderNumber = %q, want \"6ES7 151-8AB01-0AB0\"", res.OrderNumber)
	}
	if res.Firmware != "V3.2.6" {
		t.Errorf("Firmware = %q, want \"V3.2.6\"", res.Firmware)
	}
	if res.ModuleType != "IM151-8 PN/DP CPU" {
		t.Errorf("ModuleType = %q, want \"IM151-8 PN/DP CPU\"", res.ModuleType)
	}
	if res.SerialNumber != "S C-C6TW74882012" {
		t.Errorf("SerialNumber = %q, want \"S C-C6TW74882012\"", res.SerialNumber)
	}
	if res.StationName != "IM151-8-CPU" {
		t.Errorf("StationName = %q, want \"IM151-8-CPU\"", res.StationName)
	}
}
