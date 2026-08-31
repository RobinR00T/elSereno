// Command slmp-sim is a minimal MELSEC SLMP (3E-binary) TCP
// responder for exercising the slmp fingerprint plugin and the
// offensive write-gated proxy (offensive/write/slmp) end-to-end
// without a real Mitsubishi PLC.
//
// It listens on --addr (TCP), reads one 3E-binary frame at a time,
// and answers with a success response (end code 0x0000): READ CPU
// MODEL NAME (0x0101) carries a canned model + CPU-type code, DEVICE
// READ (0x0401) carries a couple of data words, and any other command
// gets a bare success. It performs NO gating of its own; it is a
// permissive upstream so the ElSereno proxy in front is the thing
// under test.
package main
