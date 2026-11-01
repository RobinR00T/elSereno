// Package wire builds and parses the DCE/RPC connectionless (CL, version
// 4) Endpoint Mapper lookup that a PROFINET IO device answers on UDP
// 34964. The request asks the EPM for the PNIO device interface
// (dea00001-6c97-11d1-8271-00a02442df7d); the device returns one entry
// whose annotation names the device type, order number and hardware and
// software revisions.
//
// Spec-grounded, NOT capture-validated: the layout follows DCE/RPC 1.1
// (C706, chapter 12 CL header and NDR), the p-net documentation of the
// PNIO UUID entities and the request bytes published with Nmap's
// profinet-cm-lookup script. No public capture of a real device's reply
// was found on 2026-10-27, so the parser checks every length and offset
// and reports what it could not decode instead of guessing.
package wire
