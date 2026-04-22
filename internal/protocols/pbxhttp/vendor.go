// Package pbxhttp is the HTTP(S) admin-page fingerprint for known
// PBX platforms. It complements the SIP plugin (5060/udp+tcp) and
// the IAX2 plugin (4569/udp) by catching PBXes whose SIP stack is
// hidden behind a session-border controller but whose management
// web is still on the public internet.
//
// It deliberately does not overlap with the generic `banner`
// plugin: banner waits for the server to speak first (useful for
// SSH / telnet / serial consoles), whereas HTTP servers only reply
// after a GET request, so they need their own probe.
package pbxhttp

import "strings"

// Vendor identifies the PBX platform fingerprinted by the HTTP
// admin response. The string value is the canonical short tag
// emitted in the finding's `factors` map and on the dashboard.
type Vendor string

// Known vendors. The list intentionally overlaps with
// `internal/protocols/sip.Vendor` — a single deployment will
// often appear in both (SIP on 5060 + web UI on 443 / 8088 /
// 5001), and deduplication happens at the scanner level.
const (
	VendorUnknown     Vendor = "unknown"
	VendorFreePBX     Vendor = "freepbx"
	VendorPBXact      Vendor = "pbxact"
	VendorThreeCX     Vendor = "3cx"
	VendorYeastar     Vendor = "yeastar"
	VendorCiscoUCM    Vendor = "cisco-ucm"
	VendorAvaya       Vendor = "avaya"
	VendorMitel       Vendor = "mitel"
	VendorGrandstream Vendor = "grandstream"
	VendorFanvil      Vendor = "fanvil"
	VendorYealink     Vendor = "yealink"
	VendorAsterisk    Vendor = "asterisk"   // plain Asterisk (HTTP Manager on 8088)
	VendorSwitchvox   Vendor = "switchvox"  // Digium Switchvox
	VendorElastix     Vendor = "elastix"    // 3CX acquired the name; legacy installs
	VendorFreeSWITCH  Vendor = "freeswitch" // mod_xml_rpc / verto
)

// vendorMatchers is a priority-ordered substring list. Needles are
// lowercase; the matcher folds case on the haystacks. More specific
// needles come first so "freepbx administration" wins before
// "asterisk".
var vendorMatchers = []struct {
	needle string
	vendor Vendor
}{
	// FreePBX admin page — Sangoma now owns both FreePBX and PBXact.
	{"freepbx administration", VendorFreePBX},
	{"freepbx", VendorFreePBX},
	{"sangoma pbxact", VendorPBXact},
	{"pbxact", VendorPBXact},

	// 3CX — web client + management console.
	{"3cx phone system", VendorThreeCX},
	{"3cx web client", VendorThreeCX},
	{"3cx webmeeting", VendorThreeCX},
	{"3cxphone", VendorThreeCX},
	{"3cx", VendorThreeCX},

	// Yeastar — multi-product line: NeoGate, S-series, P-series,
	// K2, MyPBX. Linkus is the softphone.
	{"yeastar", VendorYeastar},
	{"linkus server", VendorYeastar},
	{"neogate", VendorYeastar},
	{"mypbx", VendorYeastar},

	// Cisco UCM — Unified Communications Manager.
	{"cisco unified cm administration", VendorCiscoUCM},
	{"cisco unified communications manager", VendorCiscoUCM},
	{"ccmadmin", VendorCiscoUCM},
	{"cisco-unified-communications-manager", VendorCiscoUCM},

	// Avaya IP Office / Communication Manager.
	{"avaya aura", VendorAvaya},
	{"avaya ip office", VendorAvaya},
	{"ip office manager", VendorAvaya},
	{"communication manager", VendorAvaya},
	{"avaya", VendorAvaya},

	// Mitel — including acquired ShoreTel.
	{"mitel", VendorMitel},
	{"shoretel", VendorMitel},
	{"micollab", VendorMitel},

	// Grandstream UCM + IP phones.
	{"grandstream networks", VendorGrandstream},
	{"grandstream", VendorGrandstream},
	{"ucm6", VendorGrandstream}, // UCM6xxx series
	{"gxp", VendorGrandstream},  // GXP series IP phones
	{"gxw", VendorGrandstream},  // GXW gateways

	// Fanvil — phones + paging adapters.
	{"fanvil", VendorFanvil},

	// Yealink — phones + MVC. Title tag is the strongest signal.
	{"yealink", VendorYealink},
	{"sip-t", VendorYealink}, // SIP-T4x, SIP-T5x, SIP-T3x series

	// Plain Asterisk HTTP Manager (manager.conf + enabled=yes on
	// port 8088). Harder to detect than FreePBX because the page
	// is often blank; the distinguishing header is `Server:
	// Asterisk/<version>`.
	{"server: asterisk", VendorAsterisk},
	{"asterisk/", VendorAsterisk},

	// Digium Switchvox (commercial sibling of Asterisk).
	{"switchvox", VendorSwitchvox},
	{"digium", VendorSwitchvox},

	// Elastix (now owned by 3CX; still widely deployed).
	{"elastix", VendorElastix},

	// FreeSWITCH verto / mod_xml_rpc.
	{"freeswitch", VendorFreeSWITCH},
}

// IdentifyVendor scans the response headers + title + body text
// for known PBX brand markers. Inputs may be mixed-case; matching
// is case-insensitive (inputs are lowercased internally). The
// first match wins, priority-ordered.
//
// Returns VendorUnknown if nothing matches (which is normal —
// most HTTP servers on 443 are unrelated web apps, not PBXes).
func IdentifyVendor(headers, title, body string) Vendor {
	haystacks := []string{
		strings.ToLower(headers),
		strings.ToLower(title),
		strings.ToLower(body),
	}
	for _, m := range vendorMatchers {
		for _, h := range haystacks {
			if h != "" && strings.Contains(h, m.needle) {
				return m.vendor
			}
		}
	}
	return VendorUnknown
}

// VendorRisk returns the protocol_risk factor for a vendor. The
// tier logic mirrors `internal/protocols/sip.VendorRisk`:
//
//	90 — attack-ripe PBXes (FreePBX, 3CX, Asterisk, PBXact, Elastix)
//	85 — enterprise (Cisco UCM, Avaya, Mitel)
//	80 — SOHO appliances with default-exposed admin webs
//	     (Yeastar, Grandstream, Fanvil, Yealink)
//	75 — SIP gateways / commercial Asterisk flavours (Switchvox,
//	     FreeSWITCH)
//	70 — default for an unknown HTTP responder that nonetheless
//	     looked PBX-ish (e.g. the page title said "login" + the
//	     URL was /admin/config.php)
func VendorRisk(v Vendor) int {
	switch v { //nolint:exhaustive // VendorUnknown falls through to the default 70 at the bottom
	case VendorFreePBX, VendorThreeCX, VendorAsterisk, VendorPBXact, VendorElastix:
		return 90
	case VendorCiscoUCM, VendorAvaya, VendorMitel:
		return 85
	case VendorYeastar, VendorGrandstream, VendorFanvil, VendorYealink:
		return 80
	case VendorSwitchvox, VendorFreeSWITCH:
		return 75
	}
	return 70
}
