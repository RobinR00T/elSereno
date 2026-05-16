// Package opcuahttps is the OPC UA HTTPS (opc.https://) binding
// fingerprint plugin. v2.35+.
//
// The OPC UA spec (Part 6 — Mappings) defines three transport
// bindings:
//
//   - opc.tcp://   binary over raw TCP. Port 4840. Already
//     supported by internal/protocols/opcua.
//   - opc.wss://   binary over WebSockets+TLS. Port 4843.
//     Not yet supported.
//   - opc.https:// binary or JSON over HTTPS. Port 443 / 4843.
//     THIS PLUGIN.
//
// Why a separate plugin from `opcua`? Different ports, different
// framing (HTTP request/response vs raw UA-TCP frames), different
// failure modes (TLS handshake errors vs UA-protocol errors).
// Trying to multiplex inside the existing TCP plugin would have
// made the state machine confusing for operators reading findings.
//
// Probe surface:
//
//  1. TLS dial on (host, port).
//  2. HTTP POST to `/discovery` (the canonical discovery
//     endpoint per spec) with Content-Type
//     `application/opcua+uabinary` + a minimal binary
//     GetEndpointsRequest body.
//  3. Inspect response:
//     - HTTP 200 + Content-Type opcua+uabinary  → strong UA hit.
//     - HTTP 200 + Content-Type opcua+uajson    → strong UA hit
//     (JSON binding).
//     - HTTP 405 + UA-style Server header       → likely UA, wrong
//     method (some impls require POST on /).
//     - HTTP 404 / 400 with UA Server header    → weak UA hit.
//     - Any TLS handshake failure              → not OPC UA.
//
// Defensive only: probe never proceeds past discovery. No
// SecureChannel establishment, no session, no read/write.
// Score range 50-85 depending on strength of headers.
//
// Default port: 4843 (registered for opc.https/wss per spec).
// Operators can also point this plugin at 443 if they suspect
// OPC UA on the corporate HTTPS port (common for misconfigured
// SCADA gateways).
package opcuahttps
