// Package fox implements the ElSereno plugin for Niagara Fox
// (Tridium) on port 1911 (4911 is Fox over TLS). The client speaks
// first: a station answers a client hello ("fox a 1 -1 fox hello\n{...")
// with its own ("fox a 0 -1 fox hello\n{...") carrying fox.version,
// host name, app and OS versions and the station name. The probe sends
// nmap's fox-info hello and classifies the reply.
package fox
