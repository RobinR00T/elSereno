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

// Severity values derived from the score via SeverityFromScore.
const (
	// SeverityInfo is assigned when score < 20.
	SeverityInfo Severity = "info"
	// SeverityLow is assigned when 20 <= score < 40.
	SeverityLow Severity = "low"
	// SeverityMedium is assigned when 40 <= score < 60.
	SeverityMedium Severity = "medium"
	// SeverityHigh is assigned when 60 <= score < 80.
	SeverityHigh Severity = "high"
	// SeverityCritical is assigned when score >= 80.
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
// sysexits(3) and PITF-003 for signal-based exit codes.
type ExitCode int

// Exit codes follow sysexits(3) for the subset relevant to ElSereno.
// Signal exits are handled separately (128+signum) in cmd/elsereno.
const (
	// ExitOK indicates successful completion.
	ExitOK ExitCode = 0
	// ExitError is the generic failure code.
	ExitError ExitCode = 1
	// ExitUsage (EX_USAGE) indicates a command-line usage error.
	ExitUsage ExitCode = 64
	// ExitDataErr (EX_DATAERR) indicates bad input data.
	ExitDataErr ExitCode = 65
	// ExitNoInput (EX_NOINPUT) indicates missing input.
	ExitNoInput ExitCode = 66
	// ExitNoUser (EX_NOUSER) indicates an unknown user.
	ExitNoUser ExitCode = 67
	// ExitNoHost (EX_NOHOST) indicates an unknown host.
	ExitNoHost ExitCode = 68
	// ExitUnavail (EX_UNAVAILABLE) indicates a required service is unavailable.
	ExitUnavail ExitCode = 69
	// ExitSoftware (EX_SOFTWARE) indicates an internal software error.
	ExitSoftware ExitCode = 70
	// ExitOSErr (EX_OSERR) indicates an operating-system error.
	ExitOSErr ExitCode = 71
	// ExitOSFile (EX_OSFILE) indicates a critical OS file is missing.
	ExitOSFile ExitCode = 72
	// ExitCantOpen (EX_CANTCREAT) indicates a file cannot be created.
	ExitCantOpen ExitCode = 73
	// ExitIOErr (EX_IOERR) indicates an I/O error.
	ExitIOErr ExitCode = 74
	// ExitTempFail (EX_TEMPFAIL) indicates a transient failure; retry later.
	ExitTempFail ExitCode = 75
	// ExitProtocol (EX_PROTOCOL) indicates a protocol error with a remote host.
	ExitProtocol ExitCode = 76
	// ExitNoPerm (EX_NOPERM) indicates insufficient permissions.
	ExitNoPerm ExitCode = 77
	// ExitConfig (EX_CONFIG) indicates a configuration error.
	ExitConfig ExitCode = 78
)
