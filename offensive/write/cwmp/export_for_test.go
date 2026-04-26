//go:build offensive

package cwmp

// This file exposes unexported helpers to the test package
// (cwmp_test) so unit tests can drive recordDownload /
// resolveDownload / extractDownloadCommandKey directly without
// needing a full proxy session. Build-tagged offensive so it's
// only compiled in test builds.

// ExtractDownloadCommandKeyForTest is the exported wrapper for
// the unexported `extractDownloadCommandKey`. Test-only.
func ExtractDownloadCommandKeyForTest(body []byte) string {
	return extractDownloadCommandKey(body)
}

// RecordDownloadForTest is the exported wrapper for the
// unexported `recordDownload`. Test-only.
func RecordDownloadForTest(h *WriteGatedHandler, body []byte) {
	h.recordDownload(body)
}

// ResolveDownloadForTest is the exported wrapper for the
// unexported `resolveDownload`. Test-only.
func ResolveDownloadForTest(h *WriteGatedHandler, cmdKey string) (DownloadAuthorisation, bool) {
	return h.resolveDownload(cmdKey)
}
