//go:build offensive

package modbus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/offensive/confirm"
)

type stubDeriver struct {
	master []byte
	fail   error
}

func newDeriver() *stubDeriver { return &stubDeriver{master: []byte("test-master-key")} }

func (s *stubDeriver) Derive(info string, out []byte) error {
	if s.fail != nil {
		return s.fail
	}
	r := hkdf.New(sha256.New, s.master, nil, []byte(info))
	_, err := io.ReadFull(r, out)
	return err
}

type noopAuditor struct{ events int }

func (n *noopAuditor) Record(_ context.Context, _ confirm.AuditEvent) error {
	n.events++
	return nil
}

func TestBuild_WriteSingleCoil(t *testing.T) {
	r := Request{Op: OpWriteSingleCoil, Address: 0x0013, SingleCoilValue: true, Unit: 1, TxID: 0x0001}
	f, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x05, 0x00, 0x13, 0xFF, 0x00}
	if !bytes.Equal(f.PDU, want) {
		t.Fatalf("pdu = % x, want % x", f.PDU, want)
	}
}

func TestBuild_WriteSingleRegister(t *testing.T) {
	r := Request{Op: OpWriteSingleRegister, Address: 0x0001, SingleRegisterValue: 0x03E8, Unit: 1}
	f, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x06, 0x00, 0x01, 0x03, 0xE8}
	if !bytes.Equal(f.PDU, want) {
		t.Fatalf("pdu = % x, want % x", f.PDU, want)
	}
}

func TestBuild_WriteMultipleCoils(t *testing.T) {
	r := Request{
		Op:                 OpWriteMultipleCoils,
		Address:            0x0013,
		MultipleCoilValues: []bool{true, false, true, true, false, false, true, true, true, false},
		Unit:               1,
	}
	f, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	// FC 15 | start(2) | qty(2)=10 | bytecount(1)=2 | coil-bitfield(2)
	if f.PDU[0] != 0x0F || f.PDU[4] != 0x0A || f.PDU[5] != 0x02 {
		t.Fatalf("pdu header wrong: % x", f.PDU[:6])
	}
	// Bitfield: 0xCD, 0x01 (LSB-first across 10 coils).
	if f.PDU[6] != 0xCD || f.PDU[7] != 0x01 {
		t.Fatalf("pdu bitfield = % x, want cd 01", f.PDU[6:8])
	}
}

func TestBuild_WriteMultipleRegisters(t *testing.T) {
	r := Request{
		Op:                     OpWriteMultipleRegisters,
		Address:                0x0001,
		MultipleRegisterValues: []uint16{0x000A, 0x0102},
		Unit:                   1,
	}
	f, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x01, 0x02}
	if !bytes.Equal(f.PDU, want) {
		t.Fatalf("pdu = % x, want % x", f.PDU, want)
	}
}

func TestBuild_BadOp(t *testing.T) {
	_, err := Build(Request{Op: "nope"})
	if !errors.Is(err, ErrBadOp) {
		t.Fatalf("want ErrBadOp, got %v", err)
	}
}

func TestBuild_TooManyCoils(t *testing.T) {
	_, err := Build(Request{Op: OpWriteMultipleCoils, MultipleCoilValues: make([]bool, 2000)})
	if !errors.Is(err, ErrTooManyCoils) {
		t.Fatalf("want ErrTooManyCoils, got %v", err)
	}
}

func TestBuild_TooManyRegs(t *testing.T) {
	_, err := Build(Request{Op: OpWriteMultipleRegisters, MultipleRegisterValues: make([]uint16, 200)})
	if !errors.Is(err, ErrTooManyRegs) {
		t.Fatalf("want ErrTooManyRegs, got %v", err)
	}
}

func TestBuild_EmptyMultiPayload(t *testing.T) {
	for _, op := range []Op{OpWriteMultipleCoils, OpWriteMultipleRegisters} {
		_, err := Build(Request{Op: op})
		if !errors.Is(err, ErrEmptyPayload) {
			t.Fatalf("%s: want ErrEmptyPayload, got %v", op, err)
		}
	}
}

func TestExecute_DenialBlocksWire(t *testing.T) {
	// If Authorize refuses, Execute must not dial, let alone send.
	// We pass an address that cannot dial; any dial attempt would
	// surface as a dial error, not a typed ErrNotAccepted.
	r := Request{
		Op:                  OpWriteSingleRegister,
		Target:              "127.0.0.1:1", // would refuse connect
		Address:             0x0001,
		SingleRegisterValue: 0x0042,
		Unit:                1,
	}
	d := newDeriver()
	a := &noopAuditor{}
	c := confirm.Confirm{AcceptsWrites: false, ConfirmTarget: r.Target, ConfirmToken: ""}
	_, err := Execute(context.Background(), r, c, d, a, 50*time.Millisecond, 50*time.Millisecond)
	if !errors.Is(err, confirm.ErrNotAccepted) {
		t.Fatalf("want ErrNotAccepted, got %v", err)
	}
	if a.events != 1 {
		t.Fatalf("want exactly one audit event, got %d", a.events)
	}
}

func TestExecute_HappyPath_NetPipe(t *testing.T) {
	// End-to-end on a net.Pipe so we exercise sendOn but skip dial.
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	// Server: read one FC 6 frame, echo it back (a successful FC 6
	// response is the request echoed).
	srvDone := make(chan error, 1)
	go func() {
		req, err := mbwire.ReadFrame(server)
		if err != nil {
			srvDone <- err
			return
		}
		srvDone <- mbwire.WriteFrame(server, req)
	}()

	r := Request{
		Op:                  OpWriteSingleRegister,
		Target:              "unused",
		Address:             0x0001,
		SingleRegisterValue: 0x0042,
		Unit:                1,
	}
	frame, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sendOn(client, frame)
	if err != nil {
		t.Fatalf("sendOn: %v", err)
	}
	if !bytes.Equal(resp.PDU, frame.PDU) {
		t.Fatalf("resp pdu = % x, want echo % x", resp.PDU, frame.PDU)
	}
	if err := <-srvDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestExecute_Exception(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		req, err := mbwire.ReadFrame(server)
		if err != nil {
			return
		}
		// Craft an exception response: FC|0x80, ExIllegalDataAddress.
		fc := uint8(req.FunctionCode()) | 0x80
		_ = mbwire.WriteFrame(server, mbwire.Frame{
			MBAP: mbwire.MBAP{TxID: req.MBAP.TxID, Protocol: mbwire.ProtocolID, Unit: req.MBAP.Unit},
			PDU:  []byte{fc, uint8(mbwire.ExIllegalDataAddress)},
		})
	}()

	r := Request{Op: OpWriteSingleRegister, Address: 0xFFFE, SingleRegisterValue: 0x0001, Unit: 1}
	frame, _ := Build(r)
	_, err := sendOn(client, frame)
	if err == nil {
		t.Fatalf("expected error on exception response")
	}
}

func TestMutationFor_DeterministicHash(t *testing.T) {
	r := Request{Op: OpWriteSingleRegister, Target: "10.0.0.1:502", Address: 0x0001, SingleRegisterValue: 0x0042, Unit: 1}
	m1, err := MutationFor(r)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := MutationFor(r)
	if err != nil {
		t.Fatal(err)
	}
	if m1.PayloadHash != m2.PayloadHash {
		t.Fatalf("hash not deterministic: %x vs %x", m1.PayloadHash, m2.PayloadHash)
	}
}
