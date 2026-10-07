// Package opcuahttps is the OPC UA HTTPS (opc.https://) binding
// fingerprint plugin. v2.35+.
//
// The OPC UA spec (Part 6, Mappings) defines three transport
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
//  2. HTTP POST of a real binary GetEndpointsRequest to `/`
//     (Content-Type application/octet-stream). An HTTP 200 whose body
//     decodes as a GetEndpointsResponse is a confirmed server; the
//     endpoint count and whether any endpoint is SecurityMode=None
//     go into the finding hash.
//  3. Otherwise, fallback: POST a single 0x00 byte to `/discovery`
//     and classify the reply by its Content-Type and Server header
//     (the status code is not used).
//  4. A TLS handshake failure is an error (no finding).
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
