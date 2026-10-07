// Package proconos is a best-effort fingerprint plugin for the
// KW-Software ProConOS runtime protocol on TCP/20547.
//
// ProConOS is the runtime kernel that ships on numerous PLC
// brands Phoenix Contact ILC (which also speaks the higher-
// level PCWorx layer on TCP/1962, see internal/protocols/pcworx),
// Berghof, IPC2u, ABB / B&R / Lenze re-skins, and a long tail
// of OEM rebrands.
//
// The plugin sends the canonical 10-byte ProConOS enumeration
// request and checks the 0xcc response signature. Both come from
// two independent reference implementations that agree byte for
// byte: DigitalBond Redpoint `proconos-info.nse` (request
// `cc01000b4002000047ee`, response byte 0 = 0xcc) and the
// Praetorian nerva `proconos` plugin (same request + 0xcc
// signature). It also keeps a permissive banner classifier
// matching `PROCONOS` / `KW-Software` / `MultiProg` / `KWS-LDR` and
// the alternate-prefix form (`CA FE 00 00 CE FA DE C0`) for recall.
//
// Earlier the plugin sent `01 06 00 10` + `PROCONOS` and expected
// that prefix echoed back, which was wrong on both the send and the
// recv side and would miss real PLCs (PITF-069). The scoring stays
// best-effort (`protocol_risk` 75, `capability` ceiling 60): the
// reply is classified by its 0xcc signature or a ProConOS banner
// string only; no field (model, version) is parsed out of it. The
// request and the 0xcc reply are validated against a real capture.
//
// CVE history (cve_exposure: 7), the KW-Software runtime
// ecosystem inherits much of the Phoenix Contact ILC family's
// CVE record:
//
//   - ICSA-15-160-01 (PCWorx auth bypass + RCE, also affects
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
