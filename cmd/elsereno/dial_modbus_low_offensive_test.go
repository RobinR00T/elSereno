//go:build offensive

package main

import "testing"

// TestRequireDialAllowed_Disposition pins L6: an unrecognised
// disposition is rejected before it can be written into the audit
// chain, and delivery-requested still needs --dial-allowed.
func TestRequireDialAllowed_Disposition(t *testing.T) {
	cases := []struct {
		disp    string
		allowed bool
		wantErr bool
	}{
		{"", false, false},
		{"preview", false, false},
		{"delivery-requested", true, false},
		{"delivery-requested", false, true}, // needs --dial-allowed
		{"pwned", false, true},              // unknown disposition rejected
		{"PREVIEW", false, true},            // case-sensitive
	}
	for _, c := range cases {
		err := requireDialAllowed(c.disp, c.allowed)
		if (err != nil) != c.wantErr {
			t.Errorf("requireDialAllowed(%q,%v) err=%v wantErr=%v", c.disp, c.allowed, err, c.wantErr)
		}
	}
}

// TestBuildModbusAllowlist_RejectsZeroFC pins the loader half of L5:
// fc=0 from either --function or the YAML writes: list is rejected
// loudly instead of reaching the proxy as a silent wildcard.
func TestBuildModbusAllowlist_RejectsZeroFC(t *testing.T) {
	if _, err := buildModbusAllowlist(proxyListenOpts{functions: []uint{0}}); err == nil {
		t.Fatal("fc=0 via --function must be rejected")
	}
	if _, err := buildModbusAllowlist(proxyListenOpts{modbusWritesYAML: []proxyModbusWrite{{FC: 0}}}); err == nil {
		t.Fatal("fc:0 via YAML must be rejected")
	}
	got, err := buildModbusAllowlist(proxyListenOpts{modbusWritesYAML: []proxyModbusWrite{{FC: 6, Unit: 1}}})
	if err != nil || len(got) != 1 {
		t.Fatalf("a valid entry should pass: err=%v n=%d", err, len(got))
	}
}
