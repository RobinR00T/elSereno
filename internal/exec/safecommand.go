package exec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrDisallowedPath is returned when the resolved binary path does not
// fall under any of the allowed paths.
var ErrDisallowedPath = errors.New("exec: binary path not in allow-list")

// ErrInvalidFlag is returned when a flag fails validation (bad prefix or
// shell metacharacters).
var ErrInvalidFlag = errors.New("exec: invalid flag")

// ErrInvalidPositional is returned when the per-command positional
// validator rejects a positional argument.
var ErrInvalidPositional = errors.New("exec: invalid positional")

// ErrBypassAuditRequired is returned when CommandSpec.AllowAnyPath is
// set but no BypassAuditor was supplied. The bypass never runs
// unaudited.
var ErrBypassAuditRequired = errors.New("exec: --no-allowlist bypass requires an auditor")

// BypassEvent is recorded by a BypassAuditor whenever CommandSpec
// has AllowAnyPath=true.
type BypassEvent struct {
	Binary  string
	Reason  string
	Actor   string
	Flags   []string
	PosArgs []string
}

// BypassAuditor receives a BypassEvent whenever the path allowlist is
// bypassed. Returning an error aborts the spawn — the bypass never
// runs on a broken audit chain.
type BypassAuditor interface {
	RecordBypass(ev BypassEvent) error
}

// PositionalValidator validates a single positional argument. It
// returns nil if the argument is acceptable for the bound command.
type PositionalValidator func(arg string) error

// CommandSpec captures a subprocess invocation without ambiguity
// between flags and positional arguments (ADR-024).
type CommandSpec struct {
	// Name is the executable name (e.g. "nmap"). Must resolve via
	// exec.LookPath under an allowed path.
	Name string

	// Flags are argv elements that begin with "-" and precede the "--"
	// separator. Each element is validated against a shell-injection
	// regex.
	Flags []string

	// Positional are argv elements that appear *after* the "--"
	// separator. Typed validation is the caller's responsibility via
	// ValidatePositional.
	Positional []string

	// AllowedPaths is the list of directory prefixes the resolved Name
	// must live under. Default: exec.allowed_paths config.
	AllowedPaths []string

	// ValidatePositional is invoked per positional argument; if nil, a
	// conservative default rejects shell metacharacters only.
	ValidatePositional PositionalValidator

	// AllowAnyPath, when true, lets SafeCommand resolve Name outside
	// AllowedPaths. This is the `--no-allowlist` escape hatch and is
	// gated by a mandatory BypassAuditor — SafeCommand refuses the
	// spawn when AllowAnyPath is true AND BypassAuditor is nil OR
	// the auditor's RecordBypass returns an error.
	AllowAnyPath bool

	// BypassReason documents why the operator requested the bypass.
	// Emitted into the BypassEvent; empty values are allowed but the
	// audit entry will flag "reason=unspecified".
	BypassReason string

	// Actor identifies the operator (CLI: os.Getenv("USER")); emitted
	// into the BypassEvent.
	Actor string

	// BypassAuditor is the record sink for the bypass. Required when
	// AllowAnyPath is true.
	BypassAuditor BypassAuditor
}

// flagPattern is deliberately strict: leading "-", no metachars, no nul,
// no newline, no carriage return, no backticks, no backslashes.
var flagPattern = regexp.MustCompile(`^-[A-Za-z0-9][A-Za-z0-9._=:/+-]*$`)

// DefaultPositionalValidator rejects shell metacharacters.
func DefaultPositionalValidator(arg string) error {
	if strings.ContainsAny(arg, ";|&$`\n\r\x00") {
		return fmt.Errorf("%w: shell metacharacter in %q", ErrInvalidPositional, arg)
	}
	return nil
}

// validateFlags enforces flagPattern on every element.
func validateFlags(flags []string) error {
	for _, f := range flags {
		if f == "" || !flagPattern.MatchString(f) {
			return fmt.Errorf("%w: %q", ErrInvalidFlag, f)
		}
	}
	return nil
}

// resolveBinary looks up Name on PATH and verifies the resolved absolute
// path lives under one of AllowedPaths.
func resolveBinary(name string, allowed []string) (string, error) {
	full, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("exec: LookPath(%s): %w", name, err)
	}
	abs, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("exec: Abs(%s): %w", full, err)
	}
	for _, prefix := range allowed {
		if strings.HasPrefix(abs, strings.TrimRight(prefix, "/")+"/") {
			return abs, nil
		}
	}
	return "", fmt.Errorf("%w: %q not in %v", ErrDisallowedPath, abs, allowed)
}

// resolveBinaryAnyPath is the --no-allowlist escape hatch. It resolves
// the binary on PATH without the allowlist check.
func resolveBinaryAnyPath(name string) (string, error) {
	full, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("exec: LookPath(%s): %w", name, err)
	}
	abs, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("exec: Abs(%s): %w", full, err)
	}
	return abs, nil
}

// SafeCommand builds the validated *exec.Cmd per CommandSpec. Callers
// are expected to wire Stdin/Stdout/Stderr and invoke Run or Start
// themselves.
func SafeCommand(ctx context.Context, spec CommandSpec) (*exec.Cmd, error) {
	if spec.Name == "" {
		return nil, fmt.Errorf("%w: empty Name", ErrInvalidFlag)
	}
	allowed := spec.AllowedPaths
	if len(allowed) == 0 {
		// Fall back to the library default; callers normally set this
		// from exec.allowed_paths in the config.
		allowed = []string{"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"}
	}

	var binary string
	if spec.AllowAnyPath {
		if spec.BypassAuditor == nil {
			return nil, ErrBypassAuditRequired
		}
		var err error
		binary, err = resolveBinaryAnyPath(spec.Name)
		if err != nil {
			return nil, err
		}
		reason := spec.BypassReason
		if reason == "" {
			reason = "unspecified"
		}
		if err := spec.BypassAuditor.RecordBypass(BypassEvent{
			Binary:  binary,
			Reason:  reason,
			Actor:   spec.Actor,
			Flags:   append([]string(nil), spec.Flags...),
			PosArgs: append([]string(nil), spec.Positional...),
		}); err != nil {
			return nil, fmt.Errorf("exec: bypass audit: %w", err)
		}
	} else {
		var err error
		binary, err = resolveBinary(spec.Name, allowed)
		if err != nil {
			return nil, err
		}
	}

	if err := validateFlags(spec.Flags); err != nil {
		return nil, err
	}

	validate := spec.ValidatePositional
	if validate == nil {
		validate = DefaultPositionalValidator
	}
	for _, p := range spec.Positional {
		if err := validate(p); err != nil {
			return nil, err
		}
	}

	argv := make([]string, 0, len(spec.Flags)+len(spec.Positional)+1)
	argv = append(argv, spec.Flags...)
	argv = append(argv, "--")
	argv = append(argv, spec.Positional...)

	// The single authorised subprocess-spawn site in ElSereno. Arguments
	// are caller-validated via CommandSpec (flag regex, path allowlist,
	// typed positional validator) and the "--" separator is inserted
	// deterministically above. See ADR-024.
	cmd := exec.CommandContext(ctx, binary, argv...) // #nosec G204 -- validated CommandSpec
	return cmd, nil
}
