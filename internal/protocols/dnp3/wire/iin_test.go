package wire

import (
	"reflect"
	"testing"
)

// respAPDU builds a response APDU (FC 0x81) carrying the given IIN.
func respAPDU(iin1, iin2 uint8) []byte {
	return []byte{0xC0, 0xC0, 0x81, iin1, iin2}
}

func TestParseIIN(t *testing.T) {
	t.Parallel()
	i1, i2, ok := ParseIIN(respAPDU(IIN1DeviceRestart, IIN2ConfigCorrupt))
	if !ok || i1 != IIN1DeviceRestart || i2 != IIN2ConfigCorrupt {
		t.Fatalf("ParseIIN = (0x%02x,0x%02x,%v), want (0x80,0x20,true)", i1, i2, ok)
	}
	// A request (FC 0x05) carries no IIN.
	if _, _, ok := ParseIIN([]byte{0xC0, 0xC0, 0x05, 0x00, 0x00}); ok {
		t.Fatal("ParseIIN ok on a non-response APDU")
	}
	// Too short.
	if _, _, ok := ParseIIN([]byte{0xC0, 0xC0, 0x81, 0x00}); ok {
		t.Fatal("ParseIIN ok on a truncated APDU")
	}
}

func TestIINStateChange(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		i1, i2 uint8
		want   bool
	}{
		{IIN1DeviceRestart, 0, true},
		{IIN1DeviceTrouble, 0, true},
		{0, IIN2ConfigCorrupt, true},
		{IIN1Class1Events | IIN1NeedTime, 0, false}, // routine polling bits
		{0, IIN2FuncNotSupp, false},                 // an error, not a state change
	} {
		if got := IINStateChange(c.i1, c.i2); got != c.want {
			t.Errorf("IINStateChange(0x%02x,0x%02x) = %v, want %v", c.i1, c.i2, got, c.want)
		}
	}
}

func TestIINError(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		i2   uint8
		want bool
	}{
		{IIN2FuncNotSupp, true},
		{IIN2ObjectUnknown, true},
		{IIN2ParameterError, true},
		{IIN2ConfigCorrupt, false}, // a state change, not a per-response error
		{0, false},
	} {
		if got := IINError(c.i2); got != c.want {
			t.Errorf("IINError(0x%02x) = %v, want %v", c.i2, got, c.want)
		}
	}
}

func TestIINBits(t *testing.T) {
	t.Parallel()
	got := IINBits(IIN1DeviceRestart, IIN2ConfigCorrupt|IIN2FuncNotSupp)
	want := []string{"device_restart", "func_not_supported", "config_corrupt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IINBits = %v, want %v", got, want)
	}
	// Routine bits produce no names.
	if b := IINBits(IIN1Class1Events|IIN1NeedTime, 0); len(b) != 0 {
		t.Fatalf("routine IIN bits named: %v", b)
	}
}
