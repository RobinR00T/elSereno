package honeypot

import "testing"

func TestCheck(t *testing.T) {
	cases := []struct {
		name    string
		proto   string
		fields  map[string]string
		suspect bool
		matches int
	}{
		{"conpot s7 defaults", "s7", map[string]string{FieldSerial: "88111222", FieldStation: "Technodrome", FieldModuleType: "IM151-8 PN/DP CPU"}, true, 3},
		{"serial alone is strong", "s7", map[string]string{FieldSerial: " 88111222 "}, true, 1},
		{"real module type alone", "s7", map[string]string{FieldModuleType: "IM151-8 PN/DP CPU", FieldSerial: "S C-X4U421302009"}, false, 1},
		{"two weak bacnet", "bacnet", map[string]string{FieldVendor: "alerton technologies, inc.", FieldModel: "VAV-DD Controller"}, true, 2},
		{"other protocol", "modbus", map[string]string{FieldSerial: "88111222"}, false, 0},
		{"nothing", "s7", nil, false, 0},
	}
	for _, c := range cases {
		v := Check(c.proto, c.fields)
		if v.Suspect != c.suspect || len(v.Matches) != c.matches {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
	if len(Signatures()) == 0 {
		t.Fatal("empty catalogue")
	}
}
