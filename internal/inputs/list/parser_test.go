package list_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/list"
)

func TestParseBasic(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(`
# comment line
1.2.3.4:502
10.0.0.1
[2001:db8::1]:102
2001:db8::2
`)
	targets, err := list.Parse(context.Background(), in, list.ParseOptions{DefaultPort: 80})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(targets) != 4 {
		t.Fatalf("got %d targets, want 4", len(targets))
	}
	if got, want := targets[0].Address.String(), "1.2.3.4"; got != want {
		t.Fatalf("addr[0] = %q, want %q", got, want)
	}
	if got, want := int(targets[0].Port), 502; got != want {
		t.Fatalf("port[0] = %d, want %d", got, want)
	}
	if got, want := int(targets[1].Port), 80; got != want {
		t.Fatalf("port[1] default = %d, want 80", got)
	}
	if got, want := targets[2].Address.String(), "2001:db8::1"; got != want {
		t.Fatalf("addr[2] = %q, want %q", got, want)
	}
}

func TestParseRejectsMissingDefaultPort(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("10.0.0.1\n")
	_, err := list.Parse(context.Background(), in, list.ParseOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRejectsInvalidPort(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("10.0.0.1:99999\n")
	_, err := list.Parse(context.Background(), in, list.ParseOptions{DefaultPort: 502})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseEmpty(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("\n# only comment\n\n")
	_, err := list.Parse(context.Background(), in, list.ParseOptions{DefaultPort: 502})
	if !errors.Is(err, list.ErrEmpty) {
		t.Fatalf("got %v, want ErrEmpty", err)
	}
}

func TestParseLimit(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("1.2.3.4:1\n1.2.3.5:2\n1.2.3.6:3\n")
	ts, err := list.Parse(context.Background(), in, list.ParseOptions{Limit: 2})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(ts) != 2 {
		t.Fatalf("got %d, want 2", len(ts))
	}
}
