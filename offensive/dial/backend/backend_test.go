//go:build offensive

package backend_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"local/elsereno/offensive/dial/backend"
)

// ---- Mock ----

func TestMock_DefaultReturnsPreview(t *testing.T) {
	m := backend.NewMock()
	res, err := m.Deliver(context.Background(), "5551234567")
	if err != nil {
		t.Fatal(err)
	}
	if res.Disposition != backend.DispositionPreview {
		t.Fatalf("disposition = %q, want preview", res.Disposition)
	}
}

func TestMock_ScriptedDispositionMatches(t *testing.T) {
	m := backend.NewMock()
	m.Script["5551"] = backend.Result{
		Disposition: backend.DispositionBusy,
		Reason:      "scripted",
	}
	res, _ := m.Deliver(context.Background(), "5551234567")
	if res.Disposition != backend.DispositionBusy {
		t.Fatalf("disposition = %q, want busy", res.Disposition)
	}
	// Unscripted falls back to preview.
	res2, _ := m.Deliver(context.Background(), "9999999999")
	if res2.Disposition != backend.DispositionPreview {
		t.Fatalf("unscripted disposition = %q, want preview", res2.Disposition)
	}
}

func TestMock_RecordsCalls(t *testing.T) {
	m := backend.NewMock()
	_, _ = m.Deliver(context.Background(), "111")
	_, _ = m.Deliver(context.Background(), "222")
	calls := m.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	if calls[0].Number != "111" || calls[1].Number != "222" {
		t.Fatalf("calls order / content mismatch: %+v", calls)
	}
}

func TestMock_CancelledContextReturnsFailed(t *testing.T) {
	m := backend.NewMock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := m.Deliver(ctx, "1234567890")
	if err == nil {
		t.Fatal("expected context-cancelled error")
	}
	if res.Disposition != backend.DispositionFailed {
		t.Fatalf("disposition = %q, want failed", res.Disposition)
	}
}

// ---- ATModem with a simulated modem on a net.Pipe ----

// modemSim replies to AT commands on the peer side of a pipe.
// Reads command-per-line (\r terminator, per Hayes spec) so
// back-to-back ATZ + ATE0 produce two independent replies. A
// single-buffer reader would conflate them and deadlock.
type modemSim struct {
	dtResponse string // what to send after ATDT (e.g. "CONNECT 57600")
}

// run answers OK to ATZ/ATE0 and dtResponse to ATDT. On ATH0
// it closes the peer instead of replying — the real handler's
// hangup() doesn't wait for an OK and a net.Pipe sim that tries
// to write one deadlocks against the test-goroutine's shutdown
// sequence.
func (s *modemSim) run(peer net.Conn) {
	defer peer.Close()
	reply := func(r string) {
		_, _ = peer.Write([]byte(r + "\r\n"))
	}
	br := bufio.NewReader(peer)
	for {
		line, err := br.ReadString('\r')
		line = strings.TrimRight(line, "\r\n ")
		if err != nil && line == "" {
			return
		}
		switch {
		case startsWith(line, "ATDT"):
			reply(s.dtResponse)
		case startsWith(line, "ATZ"), startsWith(line, "ATE0"):
			reply("OK")
		case startsWith(line, "ATH0"):
			return // close — hangup() doesn't wait
		}
	}
}

func startsWith(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	return s[:len(p)] == p
}

func TestATModem_ConnectMapsToDelivered(t *testing.T) {
	client, server := net.Pipe()
	sim := &modemSim{dtResponse: "CONNECT 57600"}
	go sim.run(server)

	m := backend.NewATModem(client, "/dev/pipe", 3*time.Second)
	t.Cleanup(func() { _ = m.Close(); _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := m.Deliver(ctx, "5551234567")
	if err != nil {
		t.Fatal(err)
	}
	if res.Disposition != backend.DispositionDelivered {
		t.Fatalf("disposition = %q, raw=%q", res.Disposition, res.Raw)
	}
}

func TestATModem_BusyMapsToBusy(t *testing.T) {
	client, server := net.Pipe()
	go (&modemSim{dtResponse: "BUSY"}).run(server)
	m := backend.NewATModem(client, "/dev/pipe", 3*time.Second)
	t.Cleanup(func() { _ = m.Close(); _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := m.Deliver(ctx, "5551234567")
	if res.Disposition != backend.DispositionBusy {
		t.Fatalf("disposition = %q", res.Disposition)
	}
}

func TestATModem_NoAnswerMapsToNoAnswer(t *testing.T) {
	client, server := net.Pipe()
	go (&modemSim{dtResponse: "NO ANSWER"}).run(server)
	m := backend.NewATModem(client, "/dev/pipe", 3*time.Second)
	t.Cleanup(func() { _ = m.Close(); _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := m.Deliver(ctx, "5551234567")
	if res.Disposition != backend.DispositionNoAnswer {
		t.Fatalf("disposition = %q", res.Disposition)
	}
}

func TestATModem_NoCarrierMapsToHangup(t *testing.T) {
	client, server := net.Pipe()
	go (&modemSim{dtResponse: "NO CARRIER"}).run(server)
	m := backend.NewATModem(client, "/dev/pipe", 3*time.Second)
	t.Cleanup(func() { _ = m.Close(); _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := m.Deliver(ctx, "5551234567")
	if res.Disposition != backend.DispositionHangup {
		t.Fatalf("disposition = %q", res.Disposition)
	}
}

func TestATModem_TimeoutMapsToFailed(t *testing.T) {
	// Sim that never replies to ATDT.
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\r')
			line = strings.TrimRight(line, "\r\n ")
			if err != nil && line == "" {
				return
			}
			switch {
			case startsWith(line, "ATZ"),
				startsWith(line, "ATE0"):
				_, _ = server.Write([]byte("OK\r\n"))
			case startsWith(line, "ATH0"):
				return // close on hangup — client doesn't wait for OK
				// ATDT deliberately unmatched → timeout in readUntilResult
			}
		}
	}()
	m := backend.NewATModem(client, "/dev/pipe", 300*time.Millisecond)
	t.Cleanup(func() { _ = m.Close(); _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, _ := m.Deliver(ctx, "5551234567")
	if res.Disposition != backend.DispositionFailed {
		t.Fatalf("disposition = %q (want failed on timeout)", res.Disposition)
	}
	if res.Reason != "timeout" {
		t.Fatalf("reason = %q (want timeout)", res.Reason)
	}
}

// Compile-time interface assertion.
var _ backend.Backend = (*backend.Mock)(nil)
var _ backend.Backend = (*backend.ATModem)(nil)
var _ = io.EOF // retain the io import across refactors
