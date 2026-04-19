package wire

import "testing"

func TestClassify(t *testing.T) {
	// I-format: Control[0] low two bits = 00 or 10.
	iframe := APCI{Control: [4]byte{0x02, 0x00, 0x00, 0x00}}
	if got := Classify(iframe); got != CategoryWrite {
		t.Errorf("I-format: got %d, want %d", got, CategoryWrite)
	}
	// S-format: low two bits = 01.
	sframe := APCI{Control: [4]byte{0x01, 0x00, 0x00, 0x00}}
	if got := Classify(sframe); got != CategoryRead {
		t.Errorf("S-format: got %d, want %d", got, CategoryRead)
	}
	// U-format: low two bits = 11.
	uframe := APCI{Control: [4]byte{0x43, 0x00, 0x00, 0x00}}
	if got := Classify(uframe); got != CategoryRead {
		t.Errorf("U-format: got %d, want %d", got, CategoryRead)
	}
}

func TestBuildRefusal_STOPDT(t *testing.T) {
	out := BuildRefusal()
	if len(out) != 6 {
		t.Fatalf("len=%d, want 6", len(out))
	}
	if out[0] != 0x68 || out[1] != 0x04 || out[2] != 0x13 {
		t.Fatalf("refusal bytes wrong: % x (want 68 04 13 …)", out)
	}
}
