// Package goose dissects and passively monitors IEC 61850 substation-bus
// Layer-2 traffic: GOOSE (IEC 61850-8-1, EtherType 0x88B8) and Sampled
// Values / SV (IEC 61850-9-2, EtherType 0x88BA).
//
// Scope, mirroring the profinet package: this is an OFFLINE dissector +
// passive anomaly monitor. It takes raw Ethernet frames (from
// `tcpdump -xx`, a `.bin` capture, or a hex paste) and never opens a
// socket. Live L2 capture (raw sockets + CAP_NET_RAW) stays vNext; the
// offline workflow lets an operator audit a substation segment with
// tcpdump + this verb, and feed a frame sequence through the monitor to
// catch GOOSE spoofing.
//
// Why GOOSE matters: a GOOSE publisher signals protection events (trip a
// breaker, block a recloser) by incrementing stNum and resetting sqNum.
// The canonical attack (see e.g. the DNP3/61850 Attack & Defend
// literature) injects a frame with a HIGHER stNum than the real
// publisher, so subscribers accept the attacker's dataset and act on a
// forged trip. That, plus the simulation/test bit (which tells
// subscribers to accept simulated data) and ndsCom, are exactly the
// passively-observable signals the Monitor tracks.
//
// The BER field tags follow IEC 61850-8-1 §A.3 (the IECGoosePdu
// [APPLICATION 1] template), the same layout the Wireshark packet-goose
// dissector parses.
package goose
