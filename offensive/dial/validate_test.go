//go:build offensive

package dial

import (
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/scope"
)

func TestNormalise(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"+34 91 123 45 67", "34911234567"},
		{"(555) 123-4567", "5551234567"},
		{"00 44 20 7123 4567", "442071234567"},
		{"112", "112"},
		{"+1 911", "1911"},
		{"   666   ", "666"},
		{"00911", "911"},
		{"  ", ""},
		{"abc", ""},
	}
	for _, c := range cases {
		if got := Normalise(c.in); got != c.want {
			t.Errorf("Normalise(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidate_ShortNumbersAllHardBlocked(t *testing.T) {
	// Every emergency / short code MUST fail gate 1 with
	// ErrShortNumber, regardless of the scope.
	emptyScope := &scope.Scope{}
	for _, num := range []string{"112", "911", "999", "062", "1", "12", "123", "00112"} {
		_, err := Validate(num, emptyScope)
		if !errors.Is(err, ErrShortNumber) {
			t.Errorf("%q: want ErrShortNumber, got %v", num, err)
		}
	}
}

func TestValidate_ShortBypassAttemptFails(t *testing.T) {
	// An operator padding with a scope entry to try to bypass the
	// hard block cannot succeed: ≤3 digits never pass validate.
	sc := &scope.Scope{Dial: scope.DialDecl{BlockedNumbers: []string{}}}
	_, err := Validate("911", sc)
	if !errors.Is(err, ErrShortNumber) {
		t.Fatalf("want ErrShortNumber, got %v", err)
	}
}

func TestValidate_NilScopeStillHardBlocksShort(t *testing.T) {
	// Even with NO scope file at all, gate 1 must fire.
	_, err := Validate("112", nil)
	if !errors.Is(err, ErrShortNumber) {
		t.Fatalf("want ErrShortNumber, got %v", err)
	}
}

func TestValidate_LongNumberAllowedWithEmptyScope(t *testing.T) {
	_, err := Validate("+34 91 123 45 67", nil)
	if err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestValidate_ScopeBlockedExactMatch(t *testing.T) {
	sc := &scope.Scope{Dial: scope.DialDecl{BlockedNumbers: []string{"442071234567"}}}
	_, err := Validate("00 44 20 7123 4567", sc)
	if !errors.Is(err, ErrBlockedByScope) {
		t.Fatalf("want ErrBlockedByScope, got %v", err)
	}
}

func TestValidate_ScopeBlockedPrefix(t *testing.T) {
	sc := &scope.Scope{Dial: scope.DialDecl{BlockedNumbers: []string{"44"}}}
	_, err := Validate("+44 20 7123 4567", sc)
	if !errors.Is(err, ErrBlockedByScope) {
		t.Fatalf("want ErrBlockedByScope, got %v", err)
	}
}

func TestValidate_ScopeMiss(t *testing.T) {
	sc := &scope.Scope{Dial: scope.DialDecl{BlockedNumbers: []string{"44", "86"}}}
	_, err := Validate("+34 91 123 4567", sc)
	if err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
}

func TestValidate_EmptyNumber(t *testing.T) {
	_, err := Validate("  ", nil)
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("want ErrEmpty, got %v", err)
	}
}

func TestValidate_ErrorStringIncludesNorm(t *testing.T) {
	// When the operator sees the error, it should carry the
	// normalised number in the message for audit readability.
	_, err := Validate("+44 20 7123 4567", &scope.Scope{Dial: scope.DialDecl{BlockedNumbers: []string{"44"}}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "44") {
		t.Fatalf("error %q should mention the normalised prefix", err.Error())
	}
}
