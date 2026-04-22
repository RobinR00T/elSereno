// Package iax2 fingerprints Asterisk IAX2 (RFC 5456) servers on
// UDP port 4569. Sends a bare NEW full frame and classifies the
// response:
//
//   - ACCEPT         → IAX2 confirmed, remote accepted the call
//     (probe immediately sends HANGUP to close it).
//   - AUTHREQ        → IAX2 confirmed, remote wants auth. HIGH-
//     VALUE finding — an internet-exposed IAX2
//     registrar is almost always misconfigured.
//   - REJECT / HANGUP → IAX2 confirmed, remote refused us.
//   - any other IAX full frame → IAX2 confirmed (generic).
//   - mini-frame or non-IAX reply → not IAX2 (or audio carrier
//     on the same port — extremely rare outside
//     an active call).
//   - no reply         → no finding.
//
// Scoring: any identifiable IAX2 responder sits at the same
// protocol_risk as Asterisk over SIP (90) because IAX2 is
// Asterisk-specific — seeing it on the public internet is a
// direct PBX disclosure.
//
// Out of scope: AUTHREP (credentialed auth challenge response),
// extension enumeration via REGREQ wardial, the full IE
// (Information Element) parser. These ship with
// offensive/harvest/iax2 in v1.4.
package iax2
