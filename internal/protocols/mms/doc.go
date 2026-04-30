// Package mms is the read-only fingerprint plugin for IEC 61850
// Manufacturing Message Specification (MMS, ISO 9506) on TCP/102.
//
// MMS is the application-layer protocol every IEC 61850-8-1
// substation device speaks: protection relays (SEL, ABB, GE,
// Siemens), RTUs, merging units, station controllers, gateways.
// It's the dominant wire protocol in modern substation
// automation.
//
// Port 102 is shared with Siemens S7. Both wrap their PDUs in
// TPKT (RFC 1006) + ISO 8073 COTP. The disambiguation is the
// TSAP (Transport Service Access Point) selectors in the COTP
// Connect-Request:
//
//   - **S7-300/400/1500** uses source TSAP `01 00` and
//     destination TSAP `01 02` (rack 0, slot 2).
//   - **IEC 61850 MMS** uses source TSAP `00 01` and
//     destination TSAP `00 01` (the canonical MMS server TSAP).
//
// The plugin sends a COTP-CR with the MMS TSAPs and classifies
// the response:
//
//   - COTP-CC (Connection-Confirm, PDU type 0xD0) → MMS-
//     compatible server (positive identification at the
//     transport layer).
//   - COTP-DR (Disconnect-Request, PDU type 0x80) → server is
//     OSI-stack-aware on port 102 but rejected MMS TSAPs;
//     almost certainly S7 or another vendor-specific server
//     (negative for MMS).
//   - non-TPKT response → not OSI on port 102.
//
// Higher-confidence MMS detection (full ACSE A-ASSOCIATE-REQUEST
// with the IEC 61850-8-1 application-context name OID
// 1.0.9506.2.3) is a future tightening — the COTP-layer disambig
// is sufficient for fingerprinting.
//
// CVE history (cve_exposure: 9) — IEC 61850 MMS implementations
// have a recurring CVE record across vendors:
//
//   - CVE-2018-13802 (Siemens SIPROTEC 4 / DIGSI 4 OSI stack DoS).
//   - CVE-2020-7517  (Schneider EcoStruxure Power Operation MMS).
//   - CVE-2021-22779 (Schneider IEC 61850 stack auth bypass).
//   - CVE-2022-3008  (libIEC61850 stack RCE multi-vendor).
//   - CVE-2023-39435 (SEL-3530 RTAC MMS write-without-auth).
//
// Substation control-system blast radius: protective relays
// govern circuit-breaker trips on transmission and distribution
// grids. impact_class is set high.
package mms
