package redlion

import (
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/redlion/wire"
)

// modelReply answers the model read with a CR3 string frame carrying
// "G310C2" on the given register.
func modelReply(t *testing.T, register byte, echoes bool) string {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		buf := make([]byte, len(wire.ModelQuery))
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}
		data := append([]byte("G310C2"), 0x00)
		_, _ = server.Write(append([]byte{0x00, byte(4 + len(data)), 0x01, register, 0x03, 0x00}, data...)) // #nosec G115 -- short fixed string.
	}()
	return readModel(client, 2*time.Second, echoes)
}

// TestReadModel_FollowsTheManufacturerRule: a panel that echoed the
// manufacturer register must echo the model register (0x012A); one that
// did not gets the looser rule, like its manufacturer reply.
func TestReadModel_FollowsTheManufacturerRule(t *testing.T) {
	t.Parallel()
	if got := modelReply(t, 0x2A, true); got != "G310C2" {
		t.Errorf("echoing panel, register 0x012A: %q", got)
	}
	if got := modelReply(t, 0x2B, true); got != "" {
		t.Errorf("echoing panel, wrong register: %q, want empty", got)
	}
	if got := modelReply(t, 0x2B, false); got != "G310C2" {
		t.Errorf("non-echoing panel: %q", got)
	}
}
