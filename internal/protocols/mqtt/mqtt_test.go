package mqtt_test

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/mqtt"
	"local/elsereno/internal/protocols/mqtt/wire"
)

// brokerScript configures the fake broker's replies.
type brokerScript struct {
	connackCode  byte   // CONNACK return code
	notMQTT      bool   // reply to CONNECT with a non-CONNACK packet
	subackCode   byte   // SUBACK return code (only when connackCode == 0)
	publishTopic string // if set, PUBLISH this topic after SUBACK
}

func connack(code byte) []byte { return []byte{wire.PktCONNACK << 4, 0x02, 0x00, code} }
func suback(code byte) []byte  { return []byte{wire.PktSUBACK << 4, 0x03, 0x00, 0x01, code} }
func publish(topic string) []byte {
	body := []byte{byte(len(topic) >> 8), byte(len(topic))} // #nosec G115 -- test topic is short
	body = append(body, topic...)
	body = append(body, 0x01)                            // 1-byte message payload
	out := []byte{wire.PktPUBLISH << 4, byte(len(body))} // #nosec G115 -- test payload is short
	return append(out, body...)
}

// brokerSim stands in for an MQTT broker: one connection, scripted.
func brokerSim(t *testing.T, s brokerScript) core.Target {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr type %T", ln.Addr())
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read CONNECT.
		if _, _, err := wire.ReadPacket(conn); err != nil {
			return
		}
		if s.notMQTT {
			_, _ = conn.Write(publish("x")) // wrong packet type in reply
			return
		}
		if _, err := conn.Write(connack(s.connackCode)); err != nil {
			return
		}
		if s.connackCode != wire.ConnAccepted {
			return
		}
		// Read SUBSCRIBE, reply SUBACK.
		if _, _, err := wire.ReadPacket(conn); err != nil {
			return
		}
		if _, err := conn.Write(suback(s.subackCode)); err != nil {
			return
		}
		if s.publishTopic != "" {
			_, _ = conn.Write(publish(s.publishTopic))
		}
		// Hold the connection so the probe controls teardown.
		time.Sleep(3 * time.Second)
	}()

	port, _ := core.NewPort(addr.Port)
	return core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
}

func probe(t *testing.T, tg core.Target) *core.Finding {
	t.Helper()
	p := mqtt.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 2 * time.Second
	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

func TestProbeAnonWildcardSparkplug(t *testing.T) {
	t.Parallel()
	tg := brokerSim(t, brokerScript{
		connackCode: wire.ConnAccepted, subackCode: 0x00,
		publishTopic: "spBv1.0/plant/NBIRTH/edge1",
	})
	f := probe(t, tg)
	if f == nil {
		t.Fatal("expected a finding")
	}
	if f.Factors["auth_state"] != 90 {
		t.Errorf("anonymous access should raise auth_state to 90, got %d", f.Factors["auth_state"])
	}
	if f.Factors["capability"] != 85 {
		t.Errorf("wildcard subscribe should raise capability to 85, got %d", f.Factors["capability"])
	}
	if f.Factors["impact_class"] != 85 {
		t.Errorf("sparkplug should raise impact_class to 85, got %d", f.Factors["impact_class"])
	}
}

func TestProbeAnonNoWildcard(t *testing.T) {
	t.Parallel()
	// Anonymous accepted but the wildcard subscription is refused (0x80).
	tg := brokerSim(t, brokerScript{connackCode: wire.ConnAccepted, subackCode: wire.SubackFailure})
	f := probe(t, tg)
	if f == nil {
		t.Fatal("expected a finding")
	}
	if f.Factors["auth_state"] != 90 {
		t.Errorf("anon auth_state = %d, want 90", f.Factors["auth_state"])
	}
	if f.Factors["capability"] == 85 {
		t.Error("capability should not reach the wildcard level when subscribe is refused")
	}
}

func TestProbeAuthRequired(t *testing.T) {
	t.Parallel()
	tg := brokerSim(t, brokerScript{connackCode: wire.ConnRefusedNotAuth})
	f := probe(t, tg)
	if f == nil {
		t.Fatal("expected a finding even when auth is required (broker is exposed)")
	}
	if f.Factors["auth_state"] != 45 {
		t.Errorf("auth-required auth_state = %d, want 45 (anon path not taken)", f.Factors["auth_state"])
	}
}

func TestProbeNotMQTT(t *testing.T) {
	t.Parallel()
	tg := brokerSim(t, brokerScript{notMQTT: true})
	f := probe(t, tg)
	if f != nil {
		t.Fatalf("a non-CONNACK reply must yield no finding, got %+v", f)
	}
}
