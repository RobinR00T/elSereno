//go:build offensive

package cwmp

import "testing"

// extractRPCName parses attacker-controlled SOAP bodies from the
// ACS<->CPE path; it must never panic on malformed input.
func FuzzExtractRPCName(f *testing.F) {
	f.Add([]byte(`<soap:Envelope><soap:Body><cwmp:SetParameterValues/></soap:Body></soap:Envelope>`))
	f.Add([]byte(`<Envelope><Body></Body></Envelope>`))
	f.Add([]byte(""))
	f.Add([]byte("<<<not xml"))
	f.Add([]byte("<a><b><c><d><e/></d></c></b></a>"))
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _ = extractRPCName(body)
	})
}
