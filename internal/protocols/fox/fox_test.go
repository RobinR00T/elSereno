package fox_test

import (
	"testing"

	"local/elsereno/internal/protocols/fox"
)

func TestIsFoxBanner(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"fox a 0 -1 fox hello\n{fox.version=1.0}\n", true},
		{"fox.version=1.2.3\n", true},
		{"SSH-2.0-OpenSSH_9.0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := fox.IsFoxBanner(c.in); got != c.want {
			t.Fatalf("IsFoxBanner(%q) = %v", c.in, got)
		}
	}
}
