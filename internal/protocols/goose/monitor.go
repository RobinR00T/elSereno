package goose

import "fmt"

// Severity ranks a monitor Event.
type Severity string

// Severity levels.
const (
	SevInfo   Severity = "info"
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

// EventKind names a detected condition.
type EventKind string

// Event kinds. The stNum-family kinds are the GOOSE-spoofing tells.
const (
	// EvStateChange is a normal stNum increment (a protection event
	// fired). Logged at info: an IDS wants the transition on record.
	EvStateChange EventKind = "state_change"
	// EvStNumRegression: stNum went backwards for a gocbRef. A live
	// publisher never rewinds stNum, so this is a replay / rollback.
	EvStNumRegression EventKind = "stnum_regression"
	// EvStNumJump: stNum jumped by more than the threshold. The
	// canonical GOOSE injection uses a high stNum to override the real
	// publisher, so subscribers latch the attacker's dataset.
	EvStNumJump EventKind = "stnum_jump"
	// EvTestBitSet: the simulation/test bit is set. Subscribers told to
	// honour simulation (IEC 61850-90-5) accept the frame as live; on
	// operational traffic this is an injection tell.
	EvTestBitSet EventKind = "test_bit_set"
	// EvNdsComSet: ndsCom (needs commissioning) is set in steady state.
	EvNdsComSet EventKind = "ndscom_set"
	// EvConfRevChange: confRev changed mid-stream (reconfiguration or a
	// spoof that did not clone the real confRev).
	EvConfRevChange EventKind = "confrev_change"
	// EvSqNumAnomaly: sqNum did not advance as expected within an stNum
	// epoch (a stall, a rewind, or a gap).
	EvSqNumAnomaly EventKind = "sqnum_anomaly"
	// EvSVSmpCntRegression: SV smpCnt went backwards for an svID.
	EvSVSmpCntRegression EventKind = "sv_smpcnt_regression"
	// EvSVConfRevChange: SV confRev changed mid-stream for an svID.
	EvSVConfRevChange EventKind = "sv_confrev_change"
)

// Event is one anomaly (or notable transition) the Monitor emitted.
type Event struct {
	Kind     EventKind
	Severity Severity
	Key      string // goID (or gocbRef), or svID for SV events
	Detail   string
	StNum    uint32 // GOOSE context
	SqNum    uint32 // GOOSE context
}

// String renders an Event for the CLI.
func (e Event) String() string {
	return fmt.Sprintf("[%s] %s key=%q %s", e.Severity, e.Kind, e.Key, e.Detail)
}

type gooseState struct {
	stNum   uint32
	sqNum   uint32
	confRev uint32
}

type svState struct {
	smpCnt  uint32
	confRev uint32
	seen    bool
}

// Monitor keeps per-publisher state and flags anomalies frame by frame.
// It is single-goroutine (feed frames from one Observe caller).
type Monitor struct {
	// StNumJumpThreshold is the largest stNum increment treated as
	// normal. An increment above it raises EvStNumJump. Default 1
	// (only +1 is normal) via NewMonitor.
	StNumJumpThreshold uint32

	goose map[string]*gooseState
	sv    map[string]*svState
}

// NewMonitor returns a Monitor with sane defaults.
func NewMonitor() *Monitor {
	return &Monitor{
		StNumJumpThreshold: 1,
		goose:              map[string]*gooseState{},
		sv:                 map[string]*svState{},
	}
}

// Observe feeds one dissected frame and returns any anomaly events.
func (m *Monitor) Observe(f *Frame) []Event {
	switch f.Kind {
	case KindGOOSE:
		return m.observeGoose(f.Goose)
	case KindSV:
		return m.observeSV(f.SV)
	}
	return nil
}

// gooseKey selects the state key: goID, falling back to gocbRef.
func gooseKey(g *PDU) string {
	if g.GoID != "" {
		return g.GoID
	}
	return g.GocbRef
}

// observeGoose runs the stateless (test / ndsCom) and stateful (stNum /
// sqNum / confRev) checks for one GOOSE PDU.
func (m *Monitor) observeGoose(g *PDU) []Event {
	key := gooseKey(g)
	var evs []Event

	if g.TestPresent && g.Test {
		evs = append(evs, Event{Kind: EvTestBitSet, Severity: SevHigh, Key: key,
			Detail: "simulation/test bit set", StNum: g.StNum, SqNum: g.SqNum})
	}
	if g.NdsComPresent && g.NdsCom {
		evs = append(evs, Event{Kind: EvNdsComSet, Severity: SevMedium, Key: key,
			Detail: "ndsCom (needs commissioning) set", StNum: g.StNum, SqNum: g.SqNum})
	}

	prev, seen := m.goose[key]
	if !seen {
		m.goose[key] = &gooseState{stNum: g.StNum, sqNum: g.SqNum, confRev: g.ConfRev}
		return evs
	}
	evs = append(evs, m.gooseStatefulChecks(key, prev, g)...)
	prev.stNum, prev.sqNum, prev.confRev = g.StNum, g.SqNum, g.ConfRev
	return evs
}

// gooseStatefulChecks compares a GOOSE PDU against the last-seen state
// for its key. Extracted so observeGoose stays under funlen/gocyclo.
func (m *Monitor) gooseStatefulChecks(key string, prev *gooseState, g *PDU) []Event {
	var evs []Event
	switch {
	case g.StNum < prev.stNum:
		evs = append(evs, Event{Kind: EvStNumRegression, Severity: SevHigh, Key: key,
			Detail: fmt.Sprintf("stNum %d < previous %d", g.StNum, prev.stNum), StNum: g.StNum, SqNum: g.SqNum})
	case g.StNum > prev.stNum:
		if g.StNum-prev.stNum > m.StNumJumpThreshold {
			evs = append(evs, Event{Kind: EvStNumJump, Severity: SevHigh, Key: key,
				Detail: fmt.Sprintf("stNum jumped %d -> %d (+%d)", prev.stNum, g.StNum, g.StNum-prev.stNum),
				StNum:  g.StNum, SqNum: g.SqNum})
		} else {
			evs = append(evs, Event{Kind: EvStateChange, Severity: SevInfo, Key: key,
				Detail: fmt.Sprintf("state change stNum %d -> %d", prev.stNum, g.StNum), StNum: g.StNum, SqNum: g.SqNum})
		}
	default: // same stNum epoch: sqNum must advance
		if g.SqNum <= prev.sqNum {
			evs = append(evs, Event{Kind: EvSqNumAnomaly, Severity: SevLow, Key: key,
				Detail: fmt.Sprintf("sqNum did not advance (%d -> %d) within stNum %d", prev.sqNum, g.SqNum, g.StNum),
				StNum:  g.StNum, SqNum: g.SqNum})
		}
	}
	if g.ConfRev != prev.confRev {
		evs = append(evs, Event{Kind: EvConfRevChange, Severity: SevMedium, Key: key,
			Detail: fmt.Sprintf("confRev %d -> %d", prev.confRev, g.ConfRev), StNum: g.StNum, SqNum: g.SqNum})
	}
	return evs
}

// observeSV runs the SV continuity checks (smpCnt regression, confRev
// change) keyed on svID.
func (m *Monitor) observeSV(s *SVPDU) []Event {
	key := s.SvID
	var evs []Event
	prev, seen := m.sv[key]
	if !seen {
		m.sv[key] = &svState{smpCnt: s.SmpCnt, confRev: s.ConfRev, seen: true}
		return evs
	}
	// smpCnt wraps at its sample-rate boundary (e.g. 4000/s), so a small
	// backwards step near a wrap is normal; a large backwards step is a
	// replay. Flag only a regression that is not a plausible wrap.
	if s.SmpCnt < prev.smpCnt && prev.smpCnt-s.SmpCnt < 0x8000 {
		evs = append(evs, Event{Kind: EvSVSmpCntRegression, Severity: SevMedium, Key: key,
			Detail: fmt.Sprintf("smpCnt %d < previous %d", s.SmpCnt, prev.smpCnt)})
	}
	if s.ConfRev != prev.confRev {
		evs = append(evs, Event{Kind: EvSVConfRevChange, Severity: SevMedium, Key: key,
			Detail: fmt.Sprintf("confRev %d -> %d", prev.confRev, s.ConfRev)})
	}
	prev.smpCnt, prev.confRev = s.SmpCnt, s.ConfRev
	return evs
}
