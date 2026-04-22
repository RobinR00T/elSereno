// Package sip fingerprints SIP / PBX servers on port 5060
// (and 5061 TLS when operators point the probe there). Sends a
// single OPTIONS request and classifies the response by the
// `Server:` / `User-Agent:` header — those two fields are where
// Asterisk, FreePBX, 3CX, Cisco UCM, Mitel, Avaya IP Office,
// Yeastar, Grandstream, Fanvil, Yealink, and generic SIP
// proxies (kamailio, OpenSIPS, SER) reveal themselves.
//
// Scoring rationale: any internet-exposed SIP responder that
// advertises a full PBX vendor tag is a HIGH finding — PBX
// discovery is the start of the toll-fraud / call-hijack
// kill chain, and every commercial PBX has authenticated
// management surfaces separate from the SIP port (admin HTTP,
// AMI, ARI, proprietary protocols) that attackers pivot to.
//
// Deliberately out of scope for v1.3 chunk 1:
//   - Authentication probing (REGISTER with no credentials
//     just to see the 401 challenge — use
//     `offensive/harvest/sip` when that lands in v1.4).
//   - Extension enumeration (wardialing SIP URIs) — same
//     caveat; the scope guard would refuse without explicit
//     authorisation anyway.
//   - IAX2, SCCP, H.323 — separate plugins.
package sip
