package banner_test

import (
	"testing"

	"local/elsereno/internal/protocols/banner"
)

// DetectVendor reads a banner the target chose.
func FuzzDetectVendor(f *testing.F) {
	f.Add("220 ProFTPD Server ready")
	f.Add("SSH-2.0-OpenSSH_9.6")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		_ = banner.DetectVendor(s)
	})
}
