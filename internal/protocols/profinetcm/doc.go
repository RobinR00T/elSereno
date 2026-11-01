// Package profinetcm implements the ElSereno plugin "profinet-cm": a
// PROFINET IO device identified by IP over UDP/34964 (PNIO-CM, DCE/RPC),
// without layer-2 access. It sends one DCE/RPC Endpoint Mapper lookup for
// the PNIO device interface and reads the annotation (device type, order
// number, hardware and software revision), enough for a CVE lookup.
//
// OPT-IN (DefaultPort 0) and labelled "spec-grounded, not
// capture-validated": see the wire package for the sources. A device
// answers from an ephemeral source port, so the probe listens on an
// unconnected socket and accepts replies from the target address only,
// matched by the random activity id of the request.
package profinetcm
