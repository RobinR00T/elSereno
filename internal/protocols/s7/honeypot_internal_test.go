package s7

import "testing"

func TestComponentIdentHoneypot(t *testing.T) {
	conpot := componentIdentInfo{serialNumber: "88111222", stationName: "Technodrome", moduleType: "IM151-8 PN/DP CPU", plantDesignation: "Mouser Factory"}
	if v := conpot.honeypot(); !v.Suspect || len(v.Matches) != 4 {
		t.Fatalf("conpot defaults not flagged: %+v", v)
	}
	real := componentIdentInfo{serialNumber: "S C-X4U421302009", moduleType: "IM151-8 PN/DP CPU"}
	if v := real.honeypot(); v.Suspect {
		t.Fatalf("real module flagged: %+v", v)
	}
}
