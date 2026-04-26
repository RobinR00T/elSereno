// Package stix exports ElSereno findings as a STIX 2.1 bundle
// (OASIS standard JSON format for threat-intel sharing). Each
// finding maps to three objects in the bundle:
//
//   - An ipv4-addr or ipv6-addr SCO carrying the target's address.
//   - A network-traffic SCO carrying the target's port + protocol.
//   - An observed-data SDO referencing the network-traffic SCO,
//     with first_observed / last_observed timestamps + the
//     finding's severity in labels.
//
// The bundle is buffered in memory and emitted as a single JSON
// document on Close — STIX consumers (MISP, OpenCTI, ThreatBus)
// expect a complete bundle, not a stream of objects.
//
// All STIX object IDs are deterministic UUIDv5 keyed on the
// finding ID under the ElSereno namespace UUID. Re-running a
// scan over the same fixture produces a byte-identical bundle,
// which makes diff-based regression testing tractable.
//
// Spec reference: STIX 2.1 §3 (SDOs), §6 (SCOs), §8 (Bundles).
// Wire format: JSON per STIX 2.1 §10 (object serialisation).
package stix
