// Command fins-sim is a minimal Omron FINS/UDP responder for
// exercising the finsudp fingerprint plugin and the offensive
// write-gated proxy (offensive/write/finsudp) end-to-end without a
// real Omron PLC.
//
// It listens on --addr (UDP) and answers every well-formed FINS
// request with a success response (end code 0x0000): CONTROLLER DATA
// READ (0x05/0x01) carries a canned model string, MEMORY AREA READ
// (0x01/0x01) carries a couple of data bytes, and any other command
// gets a bare success. It performs NO gating of its own; the point is
// to be a permissive upstream so the ElSereno proxy in front is the
// thing under test. Operators who need a real Omron CPU should use
// actual hardware or a vendor simulator.
package main
