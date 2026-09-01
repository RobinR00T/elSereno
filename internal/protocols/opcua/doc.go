// Package opcua fingerprints OPC UA TCP servers on port 4840
// (OPC-UA Part 6 §7.1). Probe sends a minimal Hello (HEL) and
// classifies the server by the first response frame:
//
//   - ACK → OPC UA server that accepts our endpoint URL
//   - ERR → OPC UA server that refused (wrong endpoint, version
//     mismatch, policy reject); still a positive identification
//     because only UA-TCP speakers emit ERR
//   - anything else → not UA-TCP. OPC UA over the HTTPS binding
//     (Part 6 §7.4) is fingerprinted by the separate `opcuahttps`
//     plugin on 4843, which POSTs a real GetEndpointsRequest and
//     parses the EndpointDescription list (security posture
//     included). The GetEndpoints codec lives in wire/getendpoints.go.
//
// Write gating lives in the `offensive/write/opcua` package (built,
// behind -tags offensive): its WriteGatedHandler classifies each MSG
// chunk by service TypeId and refuses a non-allowlisted Write/Call with
// a native ServiceFault, per the ADR-040 pattern. The default build
// here stays probe-only + deny-all proxy.
package opcua
