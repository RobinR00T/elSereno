package preview_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/preview"
)

// writeFile is a tiny test helper. Returns the path on success.
func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestParse_StdinHappyPath(t *testing.T) {
	src := strings.NewReader("10.0.0.1:502\n10.0.0.2:102\n")
	got, err := preview.Parse(context.Background(), preview.Opts{
		Kind:  "stdin",
		Stdin: src,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("targets = %d, want 2", len(got))
	}
}

func TestParse_ListFile(t *testing.T) {
	path := writeFile(t, "targets.txt", "192.0.2.1:80\n192.0.2.2:443\n")
	got, err := preview.Parse(context.Background(), preview.Opts{
		Kind: "list:" + path,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("targets = %d, want 2", len(got))
	}
}

func TestParse_NmapFile(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port portid="502"><state state="open"/></port></ports>
  </host>
</nmaprun>
`
	path := writeFile(t, "scan.xml", xml)
	got, err := preview.Parse(context.Background(), preview.Opts{
		Kind: "nmap:" + path,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("targets = %d, want 1 (got %v)", len(got), got)
	}
}

func TestParse_ListMissingFile(t *testing.T) {
	_, err := preview.Parse(context.Background(), preview.Opts{
		Kind: "list:" + filepath.Join(t.TempDir(), "nonexistent.txt"),
	})
	if err == nil {
		t.Fatal("expected error on missing file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("err = %v, want os.IsNotExist=true", err)
	}
}

func TestParse_NmapMissingFile(t *testing.T) {
	_, err := preview.Parse(context.Background(), preview.Opts{
		Kind: "nmap:" + filepath.Join(t.TempDir(), "scan.xml"),
	})
	if err == nil {
		t.Fatal("expected error on missing file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("err = %v, want os.IsNotExist=true", err)
	}
}

func TestParse_UnsupportedKindReturnsTypedError(t *testing.T) {
	for _, kind := range []string{
		"shodan:cisco",
		"censys:port:502",
		"fofa:apache",
		"zoomeye:tag",
		"onyphe:something",
		"internetdb:1.2.3.4",
		"bogus",
		"",
	} {
		t.Run(kind, func(t *testing.T) {
			_, err := preview.Parse(context.Background(), preview.Opts{Kind: kind})
			var unsup preview.ErrUnsupportedKind
			if !errors.As(err, &unsup) {
				t.Fatalf("err = %v, want ErrUnsupportedKind", err)
			}
			if unsup.Kind != kind {
				t.Errorf("ErrUnsupportedKind.Kind = %q, want %q", unsup.Kind, kind)
			}
		})
	}
}

// TestParse_StdinDefaultsToOsStdin pins the nil-Stdin guard.
// We use a cancelled ctx so the underlying parser doesn't
// block on a real TTY.
func TestParse_StdinDefaultsToOsStdin(_ *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = preview.Parse(ctx, preview.Opts{Kind: "stdin"})
}

func TestErrUnsupportedKind_Error(t *testing.T) {
	e := preview.ErrUnsupportedKind{Kind: "fofa:something"}
	got := e.Error()
	for _, want := range []string{"unsupported", "fofa:something", "list", "nmap", "stdin"} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, missing %q", got, want)
		}
	}
}
