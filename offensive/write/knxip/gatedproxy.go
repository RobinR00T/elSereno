//go:build offensive

// Package knxip implements the offensive write-gate proxy for
// KNXnet/IP on UDP/3671. KNX is the dominant European Building
// Automation System (BAS): HVAC, lighting, blinds, access control,
// metering, life-safety. Mutating a KNX bus = changing physical
// state in real buildings.
//
// Architecture mirrors offensive/write/iax2 (UDP-aware
// WriteGatedHandler with the iax2 ADR-040 template):
//
//   - Per-session Authorise on the SHA-256 of a sorted allowlist.
//   - Per-datagram filtering at wire-parse time (no per-frame
//     token).
//   - The default proxy (internal/protocols/knxip) refuses every
//     client byte (read-only build can't relay UDP). This handler
//     replaces that default only when `-tags offensive` is built
//     AND the three operator fences pass.
//
// KNX-specific gating tiers:
//
//  1. **Service-type level** — refuse any KNXnet/IP service the
//     operator hasn't allowed. Always-safe set: SEARCH_REQUEST
//     (0x0201), DESCRIPTION_REQUEST (0x0204),
//     CONNECTIONSTATE_REQUEST (0x0207), DISCONNECT_REQUEST
//     (0x0209), TUNNELLING_ACK (0x0421), routing-diag
//     (0x0531/0x0532). Gateable: CONNECT_REQUEST (0x0205),
//     TUNNELLING_REQUEST (0x0420), ROUTING_INDICATION (0x0530),
//     DEVICE_CONFIGURATION_REQUEST (0x0310).
//
//  2. **APCI level** (TUNNELLING_REQUEST + ROUTING_INDICATION
//     only) — refuse any cEMI L_Data whose APCI isn't allowed.
//     APCIGroupValueRead/Response are read-only and always pass.
//     APCIGroupValueWrite, APCIIndividualAddressWrite,
//     APCIMemoryWrite, APCIRestart all require explicit allow.
//
//  3. **Group-address level** (write APCIs only) — refuse any
//     L_Data whose destination group address falls outside the
//     allowed (GroupAddr & GroupMask) ranges. Operator can
//     allowlist a single GA (mask 0xFFFF), a sub-group (mask
//     0xFF00 → all of main/middle/* ), or a main group
//     (mask 0xF800 → all of main/*/* ).
//
// Out of scope for this cycle (slated future):
//
//   - M_PropWrite / M_Reset device-mgmt object-id + PID gating.
//     Currently DEVICE_CONFIGURATION_REQUEST is gated only at
//     the service-type level; per-object granularity within the
//     cEMI body needs a Device Mgmt cEMI parser.
//   - KNXnet/IP Secure (0x09xx). Encrypted wrappers can't be
//     gated until session-key handshake is parsed.
//   - Per-IndividualAddress source filtering (refuse writes from
//     unauthorised source IAs). Operator-driven; not yet asked
//     for in field.
package knxip

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"local/elsereno/internal/protocols/knxip/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedService scopes a KNXnet/IP service-type the operator has
// authorised. For TUNNELLING_REQUEST and ROUTING_INDICATION the
// operator narrows further with AllowedAPCIs + AllowedGroups; for
// other gateable services the service-type itself is the gate.
type AllowedService struct {
	// ServiceType is the 16-bit KNXnet/IP service code (e.g.
	// 0x0420 for TUNNELLING_REQUEST).
	ServiceType uint16
}

// AllowedAPCI scopes one APCI inside a TUNNELLING_REQUEST or
// ROUTING_INDICATION. The gate refuses any L_Data whose APCI top-
// 4-bits isn't in the allowlist; read-only APCIs (Read, Response)
// are always-passed without needing entries.
type AllowedAPCI struct {
	APCI wire.APCI
}

// AllowedGroup scopes a destination Group Address range via a
// (GroupAddr, GroupMask) tuple. Set GroupMask = 0xFFFF to allow a
// single GA; 0xFF00 to allow everything in a /8 sub-block;
// 0xF800 (top 5 bits) to allow an entire main group.
type AllowedGroup struct {
	GroupAddr uint16
	GroupMask uint16
}

// Matches reports whether this AllowedGroup permits the given
// destination GA.
func (a AllowedGroup) Matches(dest uint16) bool {
	return (dest & a.GroupMask) == (a.GroupAddr & a.GroupMask)
}

// alwaysSafeServiceTypes: KNXnet/IP services that pass without
// explicit allowlist entries. These cover discovery, fingerprint,
// keep-alive, session-teardown, ack, and diag flow-control —
// nothing here mutates state.
var alwaysSafeServiceTypes = map[uint16]struct{}{
	wire.ServiceTypeSearchRequest:           {},
	wire.ServiceTypeSearchResponse:          {},
	wire.ServiceTypeDescriptionRequest:      {},
	wire.ServiceTypeDescriptionResponse:     {},
	wire.ServiceTypeConnectResponse:         {},
	wire.ServiceTypeConnectionStateRequest:  {},
	wire.ServiceTypeConnectionStateResponse: {},
	wire.ServiceTypeDisconnectRequest:       {},
	wire.ServiceTypeDisconnectResponse:      {},
	wire.ServiceTypeDeviceConfigurationAck:  {},
	wire.ServiceTypeTunnellingAck:           {},
	wire.ServiceTypeRoutingLostMessage:      {},
	wire.ServiceTypeRoutingBusy:             {},
}

// readOnlyAPCIs: cEMI APCIs that are read-only and always pass
// inside an allowlisted TUNNELLING_REQUEST without needing an
// AllowedAPCI entry. GroupValue_Read and GroupValue_Response are
// the only members.
var readOnlyAPCIs = map[wire.APCI]struct{}{
	wire.APCIGroupValueRead:     {},
	wire.APCIGroupValueResponse: {},
}

// AllowlistHash returns the deterministic SHA-256 of the full
// allowlist (services + APCIs + groups). Each dimension is sorted
// + length-prefixed so the operator's dry-run token is stable
// regardless of input order.
//
// Hash layout:
//
//	target || 0x00
//	|| sorted services as u16 BE (each)
//	|| 0xE1 || sorted APCIs as u16 BE (each)            [if any]
//	|| 0xE2 || sorted groups as (u16 GA || u16 mask) BE [if any]
//
// 0xE1 / 0xE2 separators chosen in the high range so they can't
// collide with service-type values (0x02xx-0x05xx) or APCI codes
// (max 0x3C0).
func AllowlistHash(target string, services []AllowedService, apcis []AllowedAPCI, groups []AllowedGroup) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	writeServices(h, services)
	if len(apcis) > 0 {
		_, _ = h.Write([]byte{allowlistSeparatorAPCI})
		writeAPCIs(h, apcis)
	}
	if len(groups) > 0 {
		_, _ = h.Write([]byte{allowlistSeparatorGroup})
		writeGroups(h, groups)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Hash separators picked from the 0xE0+ range — high enough not
// to collide with any KNX service code (max 0x05xx) or APCI top-
// 4-bit code (max 0x3C0).
const (
	allowlistSeparatorAPCI  byte = 0xE1
	allowlistSeparatorGroup byte = 0xE2
)

func writeServices(h io.Writer, services []AllowedService) {
	sorted := append([]AllowedService(nil), services...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ServiceType < sorted[j].ServiceType })
	var buf [2]byte
	for _, s := range sorted {
		binary.BigEndian.PutUint16(buf[:], s.ServiceType)
		_, _ = h.Write(buf[:])
	}
}

func writeAPCIs(h io.Writer, apcis []AllowedAPCI) {
	sorted := append([]AllowedAPCI(nil), apcis...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].APCI < sorted[j].APCI })
	var buf [2]byte
	for _, a := range sorted {
		binary.BigEndian.PutUint16(buf[:], uint16(a.APCI))
		_, _ = h.Write(buf[:])
	}
}

func writeGroups(h io.Writer, groups []AllowedGroup) {
	sorted := append([]AllowedGroup(nil), groups...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].GroupAddr != sorted[j].GroupAddr {
			return sorted[i].GroupAddr < sorted[j].GroupAddr
		}
		return sorted[i].GroupMask < sorted[j].GroupMask
	})
	var buf [4]byte
	for _, g := range sorted {
		binary.BigEndian.PutUint16(buf[0:2], g.GroupAddr)
		binary.BigEndian.PutUint16(buf[2:4], g.GroupMask)
		_, _ = h.Write(buf[:])
	}
}

// SessionMutation builds the confirm.Mutation that authorises the
// proxy session.
func SessionMutation(target string, services []AllowedService, apcis []AllowedAPCI, groups []AllowedGroup) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "knxip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, services, apcis, groups),
	}
}

// AllowlistHashWithGeneration is the v1.17-style cookie variant.
// generation == 0 → equals AllowlistHash. Mirrors the design used
// for modbus/iax2/sip/bacnet/cwmp.
func AllowlistHashWithGeneration(target string, services []AllowedService, apcis []AllowedAPCI, groups []AllowedGroup, generation uint32) [32]byte {
	if generation == 0 {
		return AllowlistHash(target, services, apcis, groups)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	writeServices(h, services)
	if len(apcis) > 0 {
		_, _ = h.Write([]byte{allowlistSeparatorAPCI})
		writeAPCIs(h, apcis)
	}
	if len(groups) > 0 {
		_, _ = h.Write([]byte{allowlistSeparatorGroup})
		writeGroups(h, groups)
	}
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], generation)
	_, _ = h.Write([]byte{0xFC})
	_, _ = h.Write(u32[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithGeneration builds the confirm.Mutation with
// the token-generation cookie.
func SessionMutationWithGeneration(target string, services []AllowedService, apcis []AllowedAPCI, groups []AllowedGroup, generation uint32) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "knxip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithGeneration(target, services, apcis, groups, generation),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// KNXnet/IP fail-closed UDP proxy.
type WriteGatedHandler struct {
	Target          string
	AllowedServices []AllowedService
	AllowedAPCIs    []AllowedAPCI
	AllowedGroups   []AllowedGroup
	// TokenGeneration is the v1.17-style cookie. Default 0
	// preserves the v1.55 base hash.
	TokenGeneration uint32
	Deriver         confirm.KeyDeriver
	Auditor         confirm.Auditor
	SessionConfirm  confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutationWithGeneration(h.Target, h.AllowedServices, h.AllowedAPCIs, h.AllowedGroups, h.TokenGeneration)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("knxip: write-gated proxy requires Authorise() first")

// maxDatagramSize caps a single KNX UDP read at 1500 bytes —
// KNXnet/IP frames live within Ethernet MTU; multicast routing
// frames carry a single cEMI L_Data that's at most ~250 bytes.
const maxDatagramSize = 1500

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	if h.Recorder != nil {
		client = h.Recorder.WrapClient(client)
		upstream = h.Recorder.WrapUpstream(upstream)
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream) }()
	go func() {
		_, err := io.Copy(client, upstream)
		errs <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

// forward reads datagrams from the client and routes per policy.
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer) error {
	buf := make([]byte, maxDatagramSize)
	for {
		n, readErr := client.Read(buf)
		if n > 0 {
			if err := h.routeFrame(buf[:n], upstream); err != nil {
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

// routeFrame decides what to do with one KNXnet/IP datagram.
// Refusal is silent: KNXnet/IP has no "permission denied" service
// type, and a fabricated DISCONNECT_REQUEST aimed at the wrong
// channel ID would either be ignored (best case) or trigger a
// real session teardown the operator didn't intend (worst case).
// Silent drop is the safest refusal: the client's keep-alive
// CONNECTIONSTATE_REQUEST will still pass, so a stuck session
// times out cleanly via the standard 10 s heartbeat window.
func (h *WriteGatedHandler) routeFrame(frame []byte, upstream io.Writer) error {
	st, err := wire.ServiceType(frame)
	if err != nil {
		// Too short to be a valid KNXnet/IP frame — drop silently.
		// nilerr exemption: silent drop is the deliberate refusal
		// path; surfacing wire.ErrServiceTypeMissing would tear the
		// session down on every short datagram, which a misbehaving
		// client could send at line rate.
		return nil //nolint:nilerr // silent drop is intentional refusal
	}
	if _, safe := alwaysSafeServiceTypes[st]; safe {
		_, werr := upstream.Write(frame)
		return werr
	}
	if !h.serviceAllowed(st) {
		// Service-type not in operator's allowlist — silent drop.
		return nil
	}
	// Tunnelling/routing services need APCI + group-address
	// inspection. Other allowed services pass on service-type
	// allowance alone.
	if st == wire.ServiceTypeTunnellingRequest {
		if !h.tunnellingAllowed(frame) {
			return nil
		}
	}
	if st == wire.ServiceTypeRoutingIndication {
		if !h.routingAllowed(frame) {
			return nil
		}
	}
	_, werr := upstream.Write(frame)
	return werr
}

// serviceAllowed reports whether the service-type is in the
// operator's allowlist.
func (h *WriteGatedHandler) serviceAllowed(st uint16) bool {
	for _, a := range h.AllowedServices {
		if a.ServiceType == st {
			return true
		}
	}
	return false
}

// tunnellingAllowed parses the inner cEMI L_Data and decides
// whether the (APCI, dest-group-address) pair is permitted.
// Unparseable cEMI bodies refuse — the gate doesn't allow what
// it can't classify.
func (h *WriteGatedHandler) tunnellingAllowed(frame []byte) bool {
	cemi, err := wire.ParseTunnellingCEMI(frame)
	if err != nil {
		return false
	}
	return h.cemiAllowed(cemi)
}

// routingAllowed extracts the cEMI from a ROUTING_INDICATION
// (which has NO connection-header — cEMI starts at offset 6
// directly) and applies the same APCI + GA gate.
func (h *WriteGatedHandler) routingAllowed(frame []byte) bool {
	if len(frame) < int(wire.HeaderLen) {
		return false
	}
	cemi, err := wire.ParseCEMILData(frame[wire.HeaderLen:])
	if err != nil {
		return false
	}
	return h.cemiAllowed(cemi)
}

// cemiAllowed evaluates an L_Data against the APCI + group
// allowlists.
func (h *WriteGatedHandler) cemiAllowed(cemi wire.CEMILData) bool {
	// Read-only APCIs always pass.
	if _, ro := readOnlyAPCIs[cemi.APCI]; ro {
		return true
	}
	if !h.apciAllowed(cemi.APCI) {
		return false
	}
	// Group-address gate only applies to group-addressed L_Data
	// AND only when the operator has configured group entries.
	// Empty AllowedGroups + allowed APCI = service-allow without
	// per-GA narrowing.
	if !cemi.DestIsGroup || len(h.AllowedGroups) == 0 {
		return true
	}
	for _, g := range h.AllowedGroups {
		if g.Matches(cemi.DestAddr) {
			return true
		}
	}
	return false
}

// apciAllowed reports whether the given APCI is in the operator's
// allowlist.
func (h *WriteGatedHandler) apciAllowed(apci wire.APCI) bool {
	for _, a := range h.AllowedAPCIs {
		if a.APCI == apci {
			return true
		}
	}
	return false
}
