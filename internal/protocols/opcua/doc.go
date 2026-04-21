// Package opcua fingerprints OPC UA TCP servers on port 4840
// (OPC-UA Part 6 §7.1). Probe sends a minimal Hello (HEL) and
// classifies the server by the first response frame:
//
//   - ACK → OPC UA server that accepts our endpoint URL
//   - ERR → OPC UA server that refused (wrong endpoint, version
//     mismatch, policy reject); still a positive identification
//     because only UA-TCP speakers emit ERR
//   - anything else → not UA, probably a different service on
//     4840 (which also hosts HTTPS UA variants in production
//     deployments, but the secure channel is upper-layer and
//     outside this plugin's scope)
//
// Write gating is out of scope for v1.1 — OPC UA SecureChannel +
// Session + Write service is a large surface that v1.2 opens via
// a dedicated `offensive/write/opcua` package following the
// ADR-040 WriteGatedHandler pattern.
package opcua
