// Package wire implements the minimum subset of CoDeSys V3
// (3S-Smart Software Solutions / now CoDeSys GmbH) needed for
// read-only fingerprinting on TCP/1217. CoDeSys V3 is the
// runtime layer that ships with most modern soft-PLC vendors,
// Wago PFC200, Beckhoff ADS gateway alternatives, Eaton, Bosch
// Rexroth, ABB AC500, Hilscher netX, Schneider M251/M258/M262,
// Festo CMMP/CMMS, and many smaller automation-component
// vendors.
//
// Public protocol documentation is sparse; this package's
// frame layout is reverse-engineered from open-source clients
// (libcodesys-py, codesys-rs) and ICS-CERT advisory captures
// (ICSA-12-242-01, ICSA-19-080-01, ICSA-21-014-04).
//
// This package implements ONLY a 4-byte BlockDriver magic
// hello + a banner-string classifier. The full CoDeSys V3
// service-request layer (tag-length-value APDUs over the
// BlockDriver framing, encrypted variants, the layered
// "Layer-3 / Layer-4 / Layer-7" protocol stack) is out of
// scope for v1.22 chunk 2, the fingerprint is sufficient.
//
// No service-request APDUs are issued; v1.22 chunk 2 is
// read-only by design.
package wire

import (
	"bytes"
	"errors"
)

// CoDeSys V3 Block Driver (CmpBlkDrvTcp) TCP framing, confirmed
// against the Tenable gateway PoC (pack('<II', 0xe8170100, len)) and a
// real capture (cds3.pcapng, every frame both directions opens with
// 00 01 17 e8):
//
//	Offset  Field   Size  Description
//	0..3    Magic   4     0xE8170100 (LE on the wire: 00 01 17 e8)
//	4..7    Length  4     LE: total frame length, INCLUDING this header
//	8+      PDU     …     datagram / channel / service layers (opaque here)
//
// For the read-only fingerprint we treat everything after the 4-byte
// magic as opaque: a response is identified either by its leading
// 4 bytes (the Block Driver magic) or by embedded ASCII banner strings.
const (
	// BlockDriverMagicLen is the 4-byte BlockDriver magic
	// prefix length.
	BlockDriverMagicLen = 4
)

// BlockDriverMagic is the 4-byte Block Driver magic this fingerprint
// recognises (and sends): 0xE8170100, little-endian on the wire, i.e.
// 00 01 17 e8.
//
// HISTORY (PITF-068): earlier builds used 0xCD 0xCD 0xCD 0xCD, which is
// the MSVC debug "uninitialised heap" fill pattern, almost certainly
// read off an uninitialised buffer during reverse-engineering and never
// a real CODESYS value. The correct magic is confirmed by three
// independent sources: Tenable's gateway V3 PoC (pack('<II', 0xe8170100,
// len) on send, `if magic != 0xe8170100` on recv), the Kaspersky
// ICS-CERT CODESYS Runtime paper (the PDU stack opens with the Block
// Driver layer; the runtime reads 8 bytes and compares the first 4 with
// the magic constant), and a real capture (cds3.pcapng: every frame,
// both directions, opens with 00 01 17 e8). The RECOGNITION value is now
// corrected and validated against all three (Classify / IsBlockDriverFrame).
//
// STILL DEFERRED: a complete eliciting probe. BuildHello sends only the
// 4-byte magic, which is not a full Block Driver frame (the gateway
// expects magic + length + a datagram/channel-open) and on its own
// elicits no reply. A valid channel-open PDU exists (the Tenable PoC
// builds one) but is validated only against DWRCS.exe on 11743, while
// the capture's first client PDU on 11740 embeds an endpoint IP, so no
// host-independent probe for the canonical 1217 gateway is confirmed.
// Shipping one changes the tool's active on-wire posture and is left as
// a deliberate decision. In the default read-only build, identification
// rests on the banner path below.
var BlockDriverMagic = []byte{0x00, 0x01, 0x17, 0xE8}

// CoDeSysBannerSubstrings are CoDeSys server greeting / banner
// substrings. A response containing any of these is a positive
// identification even if the BlockDriver magic isn't present in
// the first 4 bytes (some gateways prefix a plain-text greeting
// before the binary handshake).
var CoDeSysBannerSubstrings = [][]byte{
	[]byte("CoDeSys"),
	[]byte("CODESYS"),
	[]byte("3S-Smart"),
	[]byte("3S-CoDeSys"),
	[]byte("CmpHostname"),
	[]byte("CmpAppBP"),
	[]byte("CmpRuntime"),
}

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface
// on the dashboard).
var (
	// ErrShortFrame means the response is shorter than the 4-
	// byte BlockDriver magic.
	ErrShortFrame = errors.New("codesys: response shorter than 4-byte BlockDriver magic")
	// ErrNotCoDeSys means the response neither leads with the
	// BlockDriver magic nor carries a CoDeSys banner substring.
	ErrNotCoDeSys = errors.New("codesys: response is not a recognisable CoDeSys frame or banner")
)

// BuildHello returns the 4-byte Block Driver magic (0xE8170100, LE on
// the wire: 00 01 17 e8).
//
// This is the protocol's real magic prefix, NOT a complete eliciting
// probe (see BlockDriverMagic / PITF-068): a bare magic is not a full
// Block Driver frame, so a real gateway does not reply to it. In the
// default read-only build the reliable signal is a plain-text greeting
// containing one of the CoDeSysBannerSubstrings; a Block-Driver-framed
// reply, if one is observed, is recognised by its leading magic.
func BuildHello() []byte {
	out := make([]byte, BlockDriverMagicLen)
	copy(out, BlockDriverMagic)
	return out
}

// Classify validates a candidate CoDeSys V3 response. On
// success it returns a short note describing which signal
// matched (BlockDriver magic vs banner substring); on failure
// the appropriate sentinel is returned.
func Classify(buf []byte) (string, error) {
	if len(buf) < BlockDriverMagicLen {
		return "", ErrShortFrame
	}
	if bytes.HasPrefix(buf, BlockDriverMagic) {
		return "BlockDriver magic", nil
	}
	for _, sub := range CoDeSysBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return "banner=" + string(sub), nil
		}
	}
	return "", ErrNotCoDeSys
}

// IsBlockDriverFrame returns true iff the buffer's first 4
// bytes match the BlockDriver magic. Useful for the "responded
// but not a real CoDeSys handshake" branch.
func IsBlockDriverFrame(buf []byte) bool {
	return len(buf) >= BlockDriverMagicLen && bytes.HasPrefix(buf, BlockDriverMagic)
}
