package mms

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/protocols/mms/wire"
)

// realAARE is the server's AARE TPKT payload from w3h/icsmaster
// iec61850_read.pcap (result 0, accepted).
const realAARE = "02f0800e89050613010006010214020002c1003178a003800100a271830400000001a512300780010081025201300780010081025101880206006151304f020101a04a614880020780a107060528ca220203a203020100a305a103020100a40606042bce0f02a503020117be20281e020103a019a917800100810100820100830100a409800100810100820100"

func aareExchange(t *testing.T, aare []byte) (string, bool, bool) {
	t.Helper()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		if _, err := wire.ReadTPKT(server); err != nil {
			return
		}
		_ = wire.WriteTPKT(server, aare)
	}()
	note, _, associated, ok := tryACSEAssociate(client, 2*time.Second)
	return note, associated, ok
}

// TestTryACSEAssociate_ResultDecidesAssociation: the real (accepted)
// AARE associates; the same AARE with result 1 still identifies an
// IEC 61850 stack but is not an association, so no GetServerDirectory
// follows. Until 2026-10-07 both were noted "associated".
func TestTryACSEAssociate_ResultDecidesAssociation(t *testing.T) {
	t.Parallel()
	accepted, err := hex.DecodeString(realAARE)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := wire.AssociationResultMMS(accepted); err != nil || r != wire.AssociationAccepted {
		t.Fatalf("real AARE result = %d, %v; want 0", r, err)
	}
	note, associated, ok := aareExchange(t, accepted)
	if !ok || !associated || !strings.Contains(note, "associated") {
		t.Fatalf("accepted AARE: note=%q associated=%v ok=%v", note, associated, ok)
	}

	rejected := append([]byte(nil), accepted...)
	i := strings.Index(hex.EncodeToString(rejected), "a203020100") / 2
	rejected[i+4] = wire.AssociationRejectedPermanent
	note, associated, ok = aareExchange(t, rejected)
	if !ok || associated || !strings.Contains(note, "rejected") {
		t.Fatalf("rejected AARE: note=%q associated=%v ok=%v", note, associated, ok)
	}
}
