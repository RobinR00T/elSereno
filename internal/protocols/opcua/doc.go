// Package opcua fingerprints OPC UA TCP servers on port 4840
// (OPC-UA Part 6 §7.1). Probe sends a minimal Hello (HEL) and
// classifies the server by the first response frame:
//
//   - ACK → OPC UA server that accepts our endpoint URL
//   - ERR → OPC UA server that refused (wrong endpoint, version
//     mismatch, policy reject); still a positive identification
//     because only UA-TCP speakers emit ERR
//   - anything else → the UA-TCP HEL got no ACK/ERR. Before
//     giving up, Probe falls back to the OPC UA HTTPS binding
//     (Part 6 §7.4): a session-less GetEndpoints POST on the same
//     host:port. A server that answers with its EndpointDescription
//     list is a positive UA identification and reveals its security
//     posture (a SecurityMode=None endpoint scores as higher
//     exposure). See httpsprobe.go / wire/getendpoints.go.
//
// Write gating is out of scope for v1.1 — OPC UA SecureChannel +
// Session + Write service is a large surface that v1.2 opens via
// a dedicated `offensive/write/opcua` package following the
// ADR-040 WriteGatedHandler pattern.
package opcua
