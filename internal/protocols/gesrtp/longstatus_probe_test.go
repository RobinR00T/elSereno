package gesrtp

import (
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/gesrtp/wire"
)

// TestTryReadLongStatus_OperationReply: the Read Long Status reply is an
// operation response (byte 0 = 0x03). The firmware read used to demand
// the init reply's 0x01 and so never returned a firmware from a reply
// that follows the protocol (review, 2026-10-07).
func TestTryReadLongStatus_OperationReply(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		req := make([]byte, wire.MailboxLen)
		if _, err := io.ReadFull(server, req); err != nil {
			return
		}
		reply := make([]byte, wire.MailboxLen)
		reply[0] = wire.TypeResponse
		copy(reply[16:], "PACSystems V12.45.7")
		_, _ = server.Write(reply)
	}()
	if fw := tryReadLongStatus(client, 2*time.Second); fw != "V12.45.7" {
		t.Fatalf("firmware = %q, want V12.45.7 from a 0x03 operation reply", fw)
	}
}
