// Package pcworx is the read-only fingerprint plugin for the
// Phoenix Contact PCWorx runtime protocol on TCP/1962.
//
// PCWorx is the proprietary runtime protocol used by Phoenix
// Contact's Inline Controller (ILC) PLC family — ILC 130, 150,
// 170, 191, 350, 370, 390, plus the AXC F 1152 / 2152 / 3152
// distributed-control series and the RFC 460R / 470S PN
// Profinet-IO PLCs. A handful of OEM rebrands ship the same
// firmware (most notably KW-Software / Multiprog runtimes).
//
// The plugin sends the canonical 32-byte PCWorx hello (0x01
// 0x01 0x00 0x1C + "IBETH01\0" + 20 zero pad) and classifies
// the response by either:
//
//   - a 4-byte prefix echo of the hello, or
//   - any of the PCWorx banner markers in the response
//     payload (ILC, AXC F, RFC, Phoenix, PCWorx, ProConOS,
//     "FW V…", "Boot V…").
//
// The default-build proxy is fail-closed: PCWorx's deeper
// service-request layer (variable read / write / runtime
// control) is not implemented in v1.25, so the proxy refuses
// the session immediately rather than relay opaque bytes.
//
// CVE history (cve_exposure: 8) — Phoenix Contact ILC family
// has a recurring stream of advisories:
//
//   - ICSA-15-160-01 (PCWorx auth bypass + RCE).
//   - ICSA-17-201-01 (PCWorx variable-write privilege escalation).
//   - ICSA-21-082-01 (AXC F 2152 hardcoded credentials).
//   - CVE-2018-13002 (ILC 1xx config-file read without auth).
//   - CVE-2020-9436  (ILC 350/370/390 stack DoS).
package pcworx
