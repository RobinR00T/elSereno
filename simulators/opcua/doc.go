// Command opcua-sim is a minimal OPC UA (UA-TCP) stand-in used only by
// scripts/demo-opcua-proxy.sh to exercise the offensive write-gated
// proxy (offensive/write/opcua) end-to-end without a real OPC UA
// server. It accepts TCP on 127.0.0.1:4840, reads length-prefixed
// UA-TCP frames, logs each MSG service TypeId, and replies with a
// canned MSG. It is a demo aid, not a conformant device.
package main
