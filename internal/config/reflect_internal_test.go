package config

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// TestYAMLNative: defaults take the type the YAML parser gives the same
// key (PITF-096): durations and text types as strings, numbers as int,
// lists as []any, and a nil pointer as nil.
func TestYAMLNative(t *testing.T) {
	var nilPtr *int
	var nilAddr *netip.Addr // TextMarshaler with a value receiver
	cases := []struct {
		in   any
		want any
	}{
		{30 * time.Second, "30s"},
		{TLSAlways, "always"},
		{netip.MustParseAddr("192.0.2.1"), "192.0.2.1"}, // encoding.TextMarshaler
		{int64(7), 7},
		{uint16(8), 8},
		{true, true},
		{[]string{"/usr/bin"}, []any{"/usr/bin"}},
		{nilPtr, nil},
		{nilAddr, nil},
	}
	for _, c := range cases {
		if got := yamlNative(reflect.ValueOf(c.in)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("yamlNative(%#v) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

// TestStructToMap_TextStructIsLeaf: a struct that writes itself as text
// (netip.Addr) is one key, not a set of unexported fields dropped in
// silence.
func TestStructToMap_TextStructIsLeaf(t *testing.T) {
	type cfg struct {
		Bind netip.Addr `koanf:"bind"`
	}
	m, err := structToMap(cfg{Bind: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if m["bind"] != "127.0.0.1" {
		t.Fatalf("structToMap = %#v, want bind=127.0.0.1", m)
	}
}
