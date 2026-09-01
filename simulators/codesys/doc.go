// Command codesys-sim is a minimal CODESYS v3 stand-in used only by
// scripts/demo-codesys-proxy.sh to exercise the offensive write-gated
// proxy (offensive/write/codesys) end-to-end without a real CODESYS
// runtime. It accepts TCP on 127.0.0.1:11740, logs whatever the proxy
// forwards, and replies with a canned L7 response. It is a demo aid,
// not a conformant device.
package main
