//go:build offensive

package dnp3

import (
	"io"
	"log"

	"local/elsereno/internal/protocols/dnp3/wire"
)

// defaultIINErrorBurst is the number of error-bearing responses in one
// session that trips an enumeration/fuzzing alert when the operator
// does not set IINErrorBurstThreshold.
const defaultIINErrorBurst = 3

// IINEventKind classifies a notable Internal Indications observation.
type IINEventKind int

const (
	// IINStateChangeKind is emitted when the outstation reported a
	// device restart, device trouble, or a corrupt configuration.
	IINStateChangeKind IINEventKind = iota
	// IINErrorBurstKind is emitted when a run of error responses
	// (function-not-supported / object-unknown / parameter-error)
	// crossed the threshold, the signature of enumeration or fuzzing.
	IINErrorBurstKind
)

// String renders the kind for logging.
func (k IINEventKind) String() string {
	switch k {
	case IINStateChangeKind:
		return "state_change"
	case IINErrorBurstKind:
		return "error_burst"
	default:
		return "unknown"
	}
}

// IINEvent is a notable IIN observation on the outstation->master path.
type IINEvent struct {
	Kind       IINEventKind
	Src, Dest  uint16
	IIN1, IIN2 uint8
	Bits       []string // human-readable names of the set notable bits
	ErrorRun   int      // for IINErrorBurstKind: the running error-response count
}

// reportIIN dispatches a notable IIN observation to the operator's
// callback, or logs it to stderr when none is set. The poster's point
// is that the IIN rides in the reply and nobody reads it; this surfaces
// it.
func (h *WriteGatedHandler) reportIIN(ev IINEvent) {
	if h.OnIIN != nil {
		h.OnIIN(ev)
		return
	}
	log.Printf("dnp3: IIN alert [%s] src=%d dest=%d iin=0x%02x%02x bits=%v",
		ev.Kind, ev.Src, ev.Dest, ev.IIN1, ev.IIN2, ev.Bits)
}

// forwardResponses copies the outstation->master path verbatim while
// inspecting the Internal Indications in each response. Observation
// never delays or alters the data: every frame is written to the
// client before it is inspected, and a framing desync falls back to a
// raw copy so the master's stream is never corrupted.
func (h *WriteGatedHandler) forwardResponses(upstream io.Reader, client io.Writer) error {
	threshold := h.IINErrorBurstThreshold
	if threshold <= 0 {
		threshold = defaultIINErrorBurst
	}
	hdr := make([]byte, wire.HeaderLen)
	errRun := 0
	burstReported := false
	// prevStateKey de-duplicates a run of identical state-change
	// responses (a stuck Device-Restart bit) into one alert. 0 means
	// the previous response was not a state change; a real state
	// change always has at least one bit set, so 0 is a safe sentinel.
	var prevStateKey uint16
	for {
		if _, err := io.ReadFull(upstream, hdr); err != nil {
			return err
		}
		lh, err := wire.ParseHeader(hdr)
		if err != nil {
			// Framing lost: forward the bytes read and copy the rest raw.
			if _, werr := client.Write(hdr); werr != nil {
				return werr
			}
			_, cerr := io.Copy(client, upstream)
			return cerr
		}
		body := make([]byte, wire.BodyLen(lh.Length))
		if len(body) > 0 {
			if _, err := io.ReadFull(upstream, body); err != nil {
				_, _ = client.Write(hdr)
				return err
			}
		}
		// Forward verbatim first, then inspect best-effort.
		frame := make([]byte, 0, len(hdr)+len(body))
		frame = append(append(frame, hdr...), body...)
		if _, err := client.Write(frame); err != nil {
			return err
		}
		h.inspectResponse(lh, body, &errRun, threshold, &burstReported, &prevStateKey)
	}
}

// inspectResponse extracts the IIN from one response frame's body and
// emits alerts. A frame that cannot be de-blocked or is not a response
// is silently skipped (observation is best-effort).
func (h *WriteGatedHandler) inspectResponse(lh wire.Header, body []byte, errRun *int, threshold int, burstReported *bool, prevStateKey *uint16) {
	apdu, ok := wire.StripBlockCRCs(body, int(lh.Length)-5)
	if !ok {
		return
	}
	iin1, iin2, ok := wire.ParseIIN(apdu)
	if !ok {
		return
	}
	if wire.IINStateChange(iin1, iin2) {
		key := uint16(iin1)<<8 | uint16(iin2)
		if key != *prevStateKey {
			*prevStateKey = key
			h.reportIIN(IINEvent{
				Kind: IINStateChangeKind, Src: lh.Src, Dest: lh.Dest,
				IIN1: iin1, IIN2: iin2, Bits: wire.IINBits(iin1, iin2),
			})
		}
	} else {
		*prevStateKey = 0
	}
	if wire.IINError(iin2) {
		*errRun++
		if *errRun >= threshold && !*burstReported {
			*burstReported = true
			h.reportIIN(IINEvent{
				Kind: IINErrorBurstKind, Src: lh.Src, Dest: lh.Dest,
				IIN1: iin1, IIN2: iin2, Bits: wire.IINBits(iin1, iin2), ErrorRun: *errRun,
			})
		}
	}
}
