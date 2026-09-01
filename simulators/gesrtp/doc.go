// Command gesrtp-sim is a minimal GE-SRTP stand-in used only by
// scripts/demo-gesrtp-proxy.sh to exercise the offensive write-gated
// proxy (offensive/write/gesrtp) end-to-end without a real PACSystems
// PLC. It accepts TCP on 127.0.0.1:18245, reads 56-byte SRTP mailboxes,
// logs each service code, and replies with a canned response mailbox.
// It is a demo aid, not a conformant device.
package main
