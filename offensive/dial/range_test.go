//go:build offensive

package dial

import (
	"errors"
	"testing"
)

// TestExpandRange_NANP100: classic 100-block.
func TestExpandRange_NANP100(t *testing.T) {
	got, err := ExpandRange("555-0100..555-0199")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 100 {
		t.Errorf("len = %d, want 100", len(got))
	}
	if got[0] != "555-0100" {
		t.Errorf("got[0] = %q, want 555-0100", got[0])
	}
	if got[99] != "555-0199" {
		t.Errorf("got[99] = %q, want 555-0199", got[99])
	}
}

// TestExpandRange_E164: international prefix.
func TestExpandRange_E164(t *testing.T) {
	got, err := ExpandRange("+34900-100-100..+34900-100-105")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 6 {
		t.Errorf("len = %d, want 6", len(got))
	}
	if got[0] != "+34900-100-100" || got[5] != "+34900-100-105" {
		t.Errorf("endpoints wrong: %v", got)
	}
}

// TestExpandRange_LeadingZeros: 0001..0010 preserves width.
func TestExpandRange_LeadingZeros(t *testing.T) {
	got, err := ExpandRange("0001..0010")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got[0] != "0001" {
		t.Errorf("got[0] = %q, want 0001", got[0])
	}
	if got[9] != "0010" {
		t.Errorf("got[9] = %q, want 0010", got[9])
	}
}

// TestExpandRange_Single: A..A produces one number.
func TestExpandRange_Single(t *testing.T) {
	got, err := ExpandRange("555-0100..555-0100")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 || got[0] != "555-0100" {
		t.Errorf("got = %v, want [555-0100]", got)
	}
}

// TestExpandRange_Whitespace: tolerated.
func TestExpandRange_Whitespace(t *testing.T) {
	got, err := ExpandRange("  555-0100..555-0102  ")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("len = %d, want 3", len(got))
	}
}

// TestExpandRange_NoSeparator: bare number → ErrRangeMalformed.
func TestExpandRange_NoSeparator(t *testing.T) {
	_, err := ExpandRange("555-0100")
	if !errors.Is(err, ErrRangeMalformed) {
		t.Errorf("err = %v, want ErrRangeMalformed", err)
	}
}

// TestExpandRange_PrefixMismatch.
func TestExpandRange_PrefixMismatch(t *testing.T) {
	_, err := ExpandRange("555-0100..666-0100")
	if !errors.Is(err, ErrRangePrefixMismatch) {
		t.Errorf("err = %v, want ErrRangePrefixMismatch", err)
	}
}

// TestExpandRange_SuffixLength: different-digit-count suffixes.
func TestExpandRange_SuffixLength(t *testing.T) {
	_, err := ExpandRange("555-0100..555-99999")
	if !errors.Is(err, ErrRangeSuffixLength) {
		t.Errorf("err = %v, want ErrRangeSuffixLength", err)
	}
}

// TestExpandRange_Reversed: end < start.
func TestExpandRange_Reversed(t *testing.T) {
	_, err := ExpandRange("555-0199..555-0100")
	if !errors.Is(err, ErrRangeReversed) {
		t.Errorf("err = %v, want ErrRangeReversed", err)
	}
}

// TestExpandRange_TooLarge: > MaxRangeSize.
func TestExpandRange_TooLarge(t *testing.T) {
	_, err := ExpandRange("555-00000..555-99999")
	if !errors.Is(err, ErrRangeTooLarge) {
		t.Errorf("err = %v, want ErrRangeTooLarge", err)
	}
}

// TestIsRangeSpec.
func TestIsRangeSpec(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"555-0100..555-0199", true},
		{"555-0100", false},
		{"a..b", true},
		{"", false},
	} {
		if got := IsRangeSpec(tc.in); got != tc.want {
			t.Errorf("IsRangeSpec(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
