package core

import "fmt"

// Port is a validated TCP/UDP port number in the range [1, 65535].
type Port uint16

// NewPort constructs a Port, rejecting 0 and any value outside [1, 65535].
func NewPort(p int) (Port, error) {
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("%w: port %d out of range [1, 65535]", ErrValidation, p)
	}
	return Port(p), nil
}

// Severity is the qualitative class derived from a score. Derivation
// thresholds live in internal/scoring (ADR-006).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityFromScore maps an integer score in [0,100] to a Severity
// following ADR-006 thresholds.
func SeverityFromScore(score int) Severity {
	switch {
	case score >= 80:
		return SeverityCritical
	case score >= 60:
		return SeverityHigh
	case score >= 40:
		return SeverityMedium
	case score >= 20:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Confidence expresses reliability of a finding or fingerprint in [0,100].
type Confidence uint8

// NewConfidence constructs a Confidence, clamping to [0,100].
func NewConfidence(c int) Confidence {
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 100
	}
	return Confidence(c)
}

// ExitCode is the conventional Unix exit code subset we use. See
// sysexits(3) and ADR-PITF-003 for signals.
type ExitCode int

const (
	ExitOK       ExitCode = 0
	ExitError    ExitCode = 1
	ExitUsage    ExitCode = 64 // EX_USAGE
	ExitDataErr  ExitCode = 65 // EX_DATAERR
	ExitNoInput  ExitCode = 66 // EX_NOINPUT
	ExitNoUser   ExitCode = 67 // EX_NOUSER
	ExitNoHost   ExitCode = 68 // EX_NOHOST
	ExitUnavail  ExitCode = 69 // EX_UNAVAILABLE
	ExitSoftware ExitCode = 70 // EX_SOFTWARE
	ExitOSErr    ExitCode = 71 // EX_OSERR
	ExitOSFile   ExitCode = 72 // EX_OSFILE
	ExitCantOpen ExitCode = 73 // EX_CANTCREAT
	ExitIOErr    ExitCode = 74 // EX_IOERR
	ExitTempFail ExitCode = 75 // EX_TEMPFAIL
	ExitProtocol ExitCode = 76 // EX_PROTOCOL
	ExitNoPerm   ExitCode = 77 // EX_NOPERM
	ExitConfig   ExitCode = 78 // EX_CONFIG
)
