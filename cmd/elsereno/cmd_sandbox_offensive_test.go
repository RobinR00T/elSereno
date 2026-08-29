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
		} else if got[i].Scheme != "" {
			t.Errorf("got[%d].Scheme = %q, want \"\" on non-cgo build", i, got[i].Scheme)
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

// TestSandboxDiff_TwoProfilesJSON (v2.63+) — `sandbox diff
// exploit scan --json` returns a JSON object with a/b
// matching the args and only_in_a/only_in_b/common arrays
// populated. Only meaningful on the darwin+cgo build; on
// other offensive builds the verb errors with "schemes
// unavailable".
func TestSandboxDiff_TwoProfilesJSON(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"diff", "exploit", "scan", "--json"})
	err := cmd.Execute()
	if !sandboxIntrospectionAvailable {
		if err == nil {
			t.Fatalf("non-cgo: expected schemes-unavailable error")
		}
		if !strings.Contains(err.Error(), "schemes unavailable") {
			t.Errorf("non-cgo: err = %v, want 'schemes unavailable'", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("Execute: %v\nbody=%q", err, buf.String())
	}
	var got sandboxDiffResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%q", err, buf.String())
	}
	if got.A != "exploit" {
		t.Errorf("got.A = %q, want exploit", got.A)
	}
	if got.B != "scan" {
		t.Errorf("got.B = %q, want scan", got.B)
	}
	// exploit has `(allow ipc-posix-shm)` but scan doesn't.
	foundIPC := false
	for _, line := range got.OnlyInA {
		if strings.Contains(line, "ipc-posix-shm") {
			foundIPC = true
		}
	}
	if !foundIPC {
		t.Errorf("OnlyInA missing 'ipc-posix-shm' (exploit-only): %v", got.OnlyInA)
	}
	// scan has `(deny file-write*)` but exploit doesn't.
	foundDenyFW := false
	for _, line := range got.OnlyInB {
		if strings.Contains(line, "deny file-write*") {
			foundDenyFW = true
		}
	}
	if !foundDenyFW {
		t.Errorf("OnlyInB missing 'deny file-write*' (scan-only): %v", got.OnlyInB)
	}
	// Both should agree on the baseline `(version 1)` + `(deny default)`.
	foundVersion := false
	for _, line := range got.Common {
		if line == "(version 1)" {
			foundVersion = true
		}
	}
	if !foundVersion {
		t.Errorf("Common missing '(version 1)': %v", got.Common)
	}
}

// TestSandboxDiff_SelfDiffEmpty (v2.63+) — diffing a
// profile against itself should produce empty
// only_in_a + only_in_b arrays and a non-empty common.
// This is the sanity-check that the comparison is
// deterministic + line-trimming works correctly.
func TestSandboxDiff_SelfDiffEmpty(t *testing.T) {
	if !sandboxIntrospectionAvailable {
		t.Skip("schemes only available on darwin+cgo")
	}
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"diff", "dial", "dial", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var got sandboxDiffResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%q", err, buf.String())
	}
	if len(got.OnlyInA) != 0 {
		t.Errorf("self-diff OnlyInA should be empty, got %v", got.OnlyInA)
	}
	if len(got.OnlyInB) != 0 {
		t.Errorf("self-diff OnlyInB should be empty, got %v", got.OnlyInB)
	}
	if len(got.Common) == 0 {
		t.Errorf("self-diff Common should be non-empty")
	}
}

// TestSandboxDiff_UnknownProfile (v2.63+) — bogus profile
// names fail at the args layer with a hint.
func TestSandboxDiff_UnknownProfile(t *testing.T) {
	cmd := newSandboxCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"diff", "bogus", "scan"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error on bogus profile")
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("err = %v, want 'unknown profile' substring", err)
	}
}

// TestDiffSchemes_LineLevel (v2.63+) — pure unit test for
// diffSchemes() without going through cobra. Verifies that
// (a) whitespace-only lines are dropped, (b) lines are
// trimmed before comparison, (c) intersection + symmetric
// difference are correct.
func TestDiffSchemes_LineLevel(t *testing.T) {
	a := "(version 1)\n  (allow X)\n(deny Y)\n\n"
	b := "(version 1)\n(allow X)\n(allow Z)\n"
	got := diffSchemes("a", "b", a, b)

	// Both have "(version 1)" + "(allow X)" (after trim) in common.
	wantCommon := map[string]bool{"(version 1)": true, "(allow X)": true}
	for _, line := range got.Common {
		if !wantCommon[line] {
			t.Errorf("unexpected common line %q", line)
		}
		delete(wantCommon, line)
	}
	if len(wantCommon) != 0 {
		t.Errorf("missing expected common lines: %v", wantCommon)
	}

	// "(deny Y)" is only in A.
	if len(got.OnlyInA) != 1 || got.OnlyInA[0] != "(deny Y)" {
		t.Errorf("OnlyInA = %v, want [(deny Y)]", got.OnlyInA)
	}
	// "(allow Z)" is only in B.
	if len(got.OnlyInB) != 1 || got.OnlyInB[0] != "(allow Z)" {
		t.Errorf("OnlyInB = %v, want [(allow Z)]", got.OnlyInB)
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
