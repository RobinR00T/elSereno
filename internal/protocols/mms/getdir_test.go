package mms

import (
	"bytes"
	"net"
	"slices"
	"testing"
	"time"

	"local/elsereno/internal/protocols/mms/wire"
)

// TestGetServerDirectory_WrappedExchange runs the probe's
// GetServerDirectory against a server that, like a real one after the
// association, only understands MMS inside session DATA + presentation
// P-DATA, and answers the same way. The probe used to send the bare PDU
// and parse the reply as if it were bare (PITF-077).
func TestGetServerDirectory_WrappedExchange(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))

	cotpDT := []byte{0x02, 0xF0, 0x80}
	go func() {
		req, err := wire.ReadTPKT(server)
		if err != nil {
			return
		}
		want := append(append([]byte{}, cotpDT...), wire.WrapPData(wire.BuildMMSGetServerDirectoryRequest())...)
		if !bytes.Equal(req.Payload, want) {
			_ = server.Close() // a real server cannot route anything else
			return
		}
		// confirmed-ResponsePDU, invokeID 1, getNameList: LD01, LD02,
		// moreFollows FALSE.
		resp := []byte{
			0xA1, 0x13, 0x02, 0x01, 0x01,
			0xA1, 0x0E, 0xA0, 0x0C,
			0x1A, 0x04, 'L', 'D', '0', '1',
			0x1A, 0x04, 'L', 'D', '0', '2',
		}
		_ = wire.WriteTPKT(server, append(append([]byte{}, cotpDT...), wire.WrapPData(resp)...))
	}()

	lds, err := tryGetServerDirectory(client, 2*time.Second)
	if err != nil {
		t.Fatalf("tryGetServerDirectory: %v", err)
	}
	if !slices.Equal(lds, []string{"LD01", "LD02"}) {
		t.Fatalf("LDs = %q, want [LD01 LD02]", lds)
	}
}
