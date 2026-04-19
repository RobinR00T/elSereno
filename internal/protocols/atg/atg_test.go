package atg_test

import (
	"testing"

	"local/elsereno/internal/protocols/atg"
)

func TestIsATGResponse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"\x01I20100\nAPR 15, 2026 10:00\nIN-TANK INVENTORY\n\n", true},
		{"VEEDER-ROOT TLS-350", true},
		{"SSH-2.0-OpenSSH_9.0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := atg.IsATGResponse(c.in); got != c.want {
			t.Fatalf("IsATGResponse(%q) = %v", c.in, got)
		}
	}
}
