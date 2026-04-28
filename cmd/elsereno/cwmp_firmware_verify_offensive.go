//go:build offensive

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"local/elsereno/internal/audit"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
)

// verifyingTransferCompleteObserver wraps the default
// TransferComplete observer with v1.19-chunk-3 post-flash
// firmware verification. On every TransferComplete row, the
// inner observer fires synchronously (writes the structured
// log line); when the row carries a resolved Authorisation
// with a non-empty AllowlistSHA256 AND `IsSuccess()` is true,
// the wrapper spawns a goroutine that:
//
//  1. HTTP-fetches the AllowlistURL.
//  2. Streams + SHA-256-hashes the body.
//  3. Compares against AllowlistSHA256.
//  4. Emits an audit_log row with status `match` /
//     `mismatch` / `unreachable`.
//
// Catches firmware swaps on the source server (supply-chain
// attack) that would otherwise pass undetected — TR-069 doesn't
// carry the SHA-256 in TransferComplete, so the CPE-side report
// alone can't surface this class of attack.
//
// The verification is async (the goroutine outlives the proxy
// request) so a slow firmware host doesn't slow the audit
// chain. Network failures produce an `unreachable` audit row
// rather than a missed audit.
//
// timeout caps both the connection + body-read for the re-
// fetch. 5 minutes is generous for routers / IoT firmware
// (typical 30 MiB) on slow links; tune via the CLI flag.
func verifyingTransferCompleteObserver(target string, rt *offensiveRuntime, timeout time.Duration) cwmpwrite.TransferCompleteObserver {
	inner := defaultTransferCompleteObserver(target)
	return func(f cwmpwrite.TransferCompleteFields) {
		inner(f)
		if !f.IsSuccess() || f.Authorisation == nil || f.Authorisation.AllowlistSHA256 == "" {
			return
		}
		auth := *f.Authorisation
		// Goroutine-detached fetch + hash + audit. The proxy
		// request finishes before this returns; runFirmwareVerify
		// builds its own context.WithTimeout because the
		// request's ctx may already be cancelled.
		//nolint:contextcheck // intentional: post-request goroutine, fresh ctx with caller-supplied timeout.
		go runFirmwareVerify(rt, auth, target, f.CommandKey, timeout)
	}
}

// firmwareStatusUnreachable is the v1.19 chunk-3 status value
// for re-fetch failures (network error, non-2xx, timeout).
// `firmwareStatusMatch` and `firmwareStatusMismatch` are
// reused from the v1.13 chunk-2 verify-firmware command.
const firmwareStatusUnreachable = "unreachable"

// runFirmwareVerify is the goroutine body of the v1.19 chunk-3
// post-flash check. Extracted so its scope is bounded + so
// tests can drive it directly without spinning up a real
// observer.
func runFirmwareVerify(rt *offensiveRuntime, auth cwmpwrite.DownloadAuthorisation, target, commandKey string, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{Timeout: timeout}
	got, err := fetchFirmwareSHA256(ctx, client, auth.AllowlistURL)
	body := map[string]any{
		"target":           target,
		"command_key":      commandKey,
		"url":              auth.AllowlistURL,
		"expected_sha256":  auth.AllowlistSHA256,
		"download_url":     auth.DownloadURL,
		"token_generation": "n/a", // operator can correlate via the prior reload audit row
	}
	switch {
	case err != nil:
		body["status"] = firmwareStatusUnreachable
		body["reason"] = err.Error()
	case strings.EqualFold(got, auth.AllowlistSHA256):
		body["status"] = firmwareStatusMatch
		body["got_sha256"] = got
	default:
		body["status"] = firmwareStatusMismatch
		body["got_sha256"] = got
	}
	emitFirmwareVerifyAudit(ctx, rt, body)
}

// emitFirmwareVerifyAudit writes the cwmp_firmware_verify row.
// Best-effort like the other v1.17/v1.19 audit emitters: a
// failed audit-chain write doesn't propagate up.
func emitFirmwareVerifyAudit(ctx context.Context, rt *offensiveRuntime, body map[string]any) {
	if rt == nil || rt.Writer == nil {
		return
	}
	payload, err := json.Marshal(body)
	if err != nil {
		payload = []byte(`{"status":"unknown","error":"audit_payload_marshal_failed"}`)
	}
	_, _ = rt.Writer.Append(ctx, audit.Entry{
		EventType: audit.EventCWMPFirmwareVerify,
		Actor:     rt.Actor,
		Payload:   payload,
	})
}
