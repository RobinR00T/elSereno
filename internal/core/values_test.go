package core_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/core"
)

func TestNewPort(t *testing.T) {
	cases := []struct {
		in      int
		wantErr bool
	}{
		{0, true},
		{-1, true},
		{1, false},
		{80, false},
		{65535, false},
		{65536, true},
	}
	for _, tc := range cases {
		p, err := core.NewPort(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NewPort(%d) expected error, got %d", tc.in, p)
			}
			if !errors.Is(err, core.ErrValidation) {
				t.Fatalf("NewPort(%d) err = %v, want ErrValidation", tc.in, err)
			}
		} else if err != nil {
			t.Fatalf("NewPort(%d) unexpected err %v", tc.in, err)
		}
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score int
		want  core.Severity
	}{
		{0, core.SeverityInfo},
		{19, core.SeverityInfo},
		{20, core.SeverityLow},
		{39, core.SeverityLow},
		{40, core.SeverityMedium},
		{59, core.SeverityMedium},
		{60, core.SeverityHigh},
		{79, core.SeverityHigh},
		{80, core.SeverityCritical},
		{100, core.SeverityCritical},
	}
	for _, tc := range cases {
		got := core.SeverityFromScore(tc.score)
		if got != tc.want {
			t.Fatalf("SeverityFromScore(%d) = %s, want %s", tc.score, got, tc.want)
		}
	}
}
