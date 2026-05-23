//go:build offensive

// v2.62 — tests for `elsereno sandbox` parent verb + `list`
// and `introspect` subverbs. Built for every offensive build
// (regardless of cgo) — assertions branch on the
// `sandboxIntrospectionAvailable` const so the same test
// file fences behaviour across the cgo / non-cgo paths.

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestSandboxList_Text — `sandbox list` (text mode) prints
// the 4 profile names, one per line, in declaration order.
func TestSandboxList_Text(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := strings.TrimSpace(buf.String())
	want := "exploit\nharvest\ndial\nscan"
	if got != want {
		t.Errorf("list output =\n%s\nwant\n%s", got, want)
	}
}

// TestSandboxList_JSON — `sandbox list --json` emits a stable
// JSON array (alphabetical-by-declaration; not sorted —
// declaration order from Profiles()).
func TestSandboxList_JSON(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var got []string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%q", err, buf.String())
	}
	want := []string{"exploit", "harvest", "dial", "scan"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestSandboxIntrospect_UnknownProfile — bogus profile name
// errors at the args-validation layer (before
// schemeForProfile is even called), with a hint to run
// `sandbox list`.
func TestSandboxIntrospect_UnknownProfile(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"introspect", "bogus"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error on unknown profile; got nil")
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("err = %v, want 'unknown profile' substring", err)
	}
}

// TestSandboxIntrospect_AllJSON — `--all --format=json` emits
// 4 entries (one per recognised profile) with the same
// profile-name order as Profiles(). On the darwin+cgo build
// every Scheme is non-empty; on every other offensive build
// every Scheme is the empty-string sentinel.
func TestSandboxIntrospect_AllJSON(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"introspect", "--all", "--format=json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var got []sandboxSchemeResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%q", err, buf.String())
	}
	wantNames := []string{"exploit", "harvest", "dial", "scan"}
	if len(got) != len(wantNames) {
		t.Fatalf("len = %d, want %d", len(got), len(wantNames))
	}
	for i, n := range wantNames {
		if got[i].Profile != n {
			t.Errorf("got[%d].Profile = %q, want %q", i, got[i].Profile, n)
		}
		if sandboxIntrospectionAvailable {
			if got[i].Scheme == "" {
				t.Errorf("got[%d].Scheme is empty on darwin+cgo (introspection should be available)", i)
			}
			if !strings.Contains(got[i].Scheme, "(version 1)") {
				t.Errorf("got[%d].Scheme missing (version 1) header", i)
			}
		} else {
			if got[i].Scheme != "" {
				t.Errorf("got[%d].Scheme = %q, want \"\" on non-cgo build", i, got[i].Scheme)
			}
		}
	}
}

// TestSandboxIntrospect_AllMutexWithPositional — passing
// both --all and a positional PROFILE arg is rejected with
// a clear message (not silently ignoring one).
func TestSandboxIntrospect_AllMutexWithPositional(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"introspect", "--all", "dial"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error when --all + positional are both supplied")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err = %v, want 'mutually exclusive' substring", err)
	}
}

// TestSandboxIntrospect_BadFormat — unsupported --format
// values are rejected with a usage error.
func TestSandboxIntrospect_BadFormat(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"introspect", "dial", "--format=yaml"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error on --format=yaml")
	}
	if !strings.Contains(err.Error(), "format must be text or json") {
		t.Errorf("err = %v, want 'format must be text or json' substring", err)
	}
}

// TestSandboxIntrospect_TextSingle — `sandbox introspect dial`
// (text mode, single profile) prints a `# profile=dial`
// header followed by the .sb scheme body on cgo builds, or
// just the header line on non-cgo builds (empty body).
func TestSandboxIntrospect_TextSingle(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"introspect", "dial"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# profile=dial") {
		t.Errorf("output missing '# profile=dial' header: %q", out)
	}
	if sandboxIntrospectionAvailable {
		if !strings.Contains(out, "(deny network*)") {
			t.Errorf("darwin+cgo: output missing dial-specific '(deny network*)': %q", out)
		}
	}
}
