// Package proconos is a best-effort fingerprint plugin for the
// KW-Software ProConOS runtime protocol on TCP/20547.
//
// ProConOS is the runtime kernel that ships on numerous PLC
// brands — Phoenix Contact ILC (which also speaks the higher-
// level PCWorx layer on TCP/1962, see internal/protocols/pcworx),
// Berghof, IPC2u, ABB / B&R / Lenze re-skins, and a long tail
// of OEM rebrands.
//
// **HONEST SCOPE NOTE — best-effort, needs validation**: public
// references to the ProConOS handshake conflict. The plugin
// implements the variant that matches the Wireshark dissector
// in master + the metasploit auxiliary scanner module
// (`01 06 00 10` + `PROCONOS` + 4-byte zero pad). It also
// accepts the alternate-prefix form (`CA FE 00 00 CE FA DE C0`)
// found in older Berghof/Lenze captures, plus a permissive
// banner classifier matching `PROCONOS` / `KW-Software` /
// `MultiProg` / `KWS-LDR` markers.
//
// Until at least one of {real-PLC pcap, lab confirmation, ICS
// Wireshark capture} is available, operators should treat
// positive identifications as **confidence ≈ 0.7** rather than
// the ≈ 0.95 the v1.20-v1.25 fingerprint plugins produce. The
// plugin's scoring reflects this — `protocol_risk` defaults to
// 75 (vs 80 for codesys) and `capability` ceiling is 60 (vs
// 75 for codesys / pcworx).
//
// CVE history (cve_exposure: 7) — the KW-Software runtime
// ecosystem inherits much of the Phoenix Contact ILC family's
// CVE record:
//
//   - ICSA-15-160-01 (PCWorx auth bypass + RCE — also affects
//     ProConOS-only Berghof + Lenze deployments).
//   - ICSA-17-201-01 (PCWorx + ProConOS variable-write
//     privilege escalation).
//   - ICSA-18-296-01 (KW Multiprog development environment
//     RCE).
//
// Default-build proxy is fail-closed. Future offensive variant
// is a v1.X candidate once test vectors against a real Berghof
// or IPC2u runtime are available.
package proconos
