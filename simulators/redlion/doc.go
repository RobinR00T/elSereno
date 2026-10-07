// Command redlion-sim is a minimal Red Lion Crimson v3 stand-in used
// only by scripts/demo-redlion-proxy.sh to exercise the offensive
// write-gated proxy (offensive/write/redlion) end-to-end without a
// real Crimson panel. It accepts TCP on 127.0.0.1:7890, reads CR3
// frames, logs each, and replies with a canned CR3 response; the two
// identity reads of cr3-fingerprint.nse get "Red Lion Controls" and
// "G310C2" instead. It is a demo aid, not a conformant device.
package main
