//go:build offensive

package dial

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"local/elsereno/internal/scope"
)

// Errors returned by Validate. Callers use errors.Is so the audit
// layer can map to the right denied_reason.
var (
	// ErrEmpty — number is empty or non-digit-only.
	ErrEmpty = errors.New("dial: empty or non-digit number")
	// ErrShortNumber — the UNBYPASSABLE ≤3-digit hard block fired
	// (ADR-041 gate 1). This includes emergency services (112, 911,
	// 999, 062) and premium short codes.
	ErrShortNumber = errors.New("dial: ≤3-digit numbers are hard-blocked")
	// ErrBlockedByScope — scope.yaml's blocked_numbers matched.
	ErrBlockedByScope = errors.New("dial: blocked by scope")
)

// Normalise takes operator input (with spaces, dashes, leading + or
// 00, parens) and returns a digits-only string. Country-code prefixes
// are preserved — the operator's intent is auditable.
//
// Examples:
//
//	"+34 91 123 45 67"     -> "34911234567"
//	"(555) 123-4567"        -> "5551234567"
//	"00 44 20 7123 4567"    -> "442071234567"
//	"112"                    -> "112"
func Normalise(in string) string {
	// Strip a leading "+" or a leading "00" (international prefix).
	// Both are preserved as digits in the inner loop if they survive;
	// here we only discard the very common prefix noise.
	s := strings.TrimSpace(in)
	s = strings.TrimPrefix(s, "+")
	s = strings.TrimPrefix(s, "00")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Validate is the dial guard. It returns (normalised, nil) on success
// and (normalised, typedError) on rejection. The normalised form is
// the caller-visible number for audit + confirm.Mutation.Target.
//
// Gate order (ADR-041):
//  1. Hard ≤3-digit refusal. Unbypassable. No config, no flag, no
//     build tag can override this.
//  2. scope.yaml blocked_numbers match (prefix or exact).
//  3. Triple-confirm lives in offensive/confirm.Authorize; the caller
//     runs that separately after Validate returns ok.
func Validate(number string, sc *scope.Scope) (string, error) {
	norm := Normalise(number)
	if norm == "" {
		return "", fmt.Errorf("%w: input %q", ErrEmpty, number)
	}
	if len(norm) <= 3 {
		return norm, fmt.Errorf("%w: len=%d", ErrShortNumber, len(norm))
	}
	if err := sc.CheckDial(norm); err != nil {
		return norm, fmt.Errorf("%w: %w", ErrBlockedByScope, err)
	}
	return norm, nil
}
