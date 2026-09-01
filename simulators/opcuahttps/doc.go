// Command opcuahttps-sim is a minimal OPC UA HTTPS stand-in used only by
// scripts/demo-opcua-https-fingerprint.sh to exercise the opcua
// plugin's HTTPS GetEndpoints fallback without a real OPC UA server. It
// serves a fixed GetEndpointsResponse (one endpoint SecurityMode=None)
// over TLS with a self-signed cert. It is a demo aid, not a conformant
// device.
package main
