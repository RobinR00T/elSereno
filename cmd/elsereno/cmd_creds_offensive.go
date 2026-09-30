//go:build offensive

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/offensive/creds"
)

// newCredsCheckCmd is the opt-in default-credential check (offensive
// build). AUTHORIZED USE ONLY: it verifies a small set of PUBLISHED vendor
// default credentials against a device's own web UI, for an operator
// auditing infrastructure they are authorized to test. It refuses without
// --confirm-authorized.
func newCredsCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "creds-check",
		Short: "Verify published default credentials (offensive, AUTHORIZED USE ONLY)",
	}
	cmd.AddCommand(newCredsCheckHTTPCmd())
	return cmd
}

func newCredsCheckHTTPCmd() *cobra.Command {
	var target string
	var timeout time.Duration
	var jsonOut, confirmAuthorized bool
	cmd := &cobra.Command{
		Use:   "http",
		Short: "Check published HTTP Basic default credentials on a device web UI",
		Long: `Verifies whether a device web UI accepts any of a small, curated set
of PUBLISHED vendor default HTTP Basic credentials (admin/admin, root/root,
documented Siemens/Moxa defaults, ...). It first GETs the URL with no
credentials: only if that returns 401/403 does it try the defaults, so a
page that does not gate on Basic auth is never misreported. Every request
is a GET; it never changes state.

This evidences NIST SP 800-82 Rev. 4 Table 13, "Vendor default passwords
are used" (see docs/standards/nist-sp800-82r4.md). It is a targeted
verification of documented defaults, not a brute-force or wordlist attack.

AUTHORIZED USE ONLY. Run this only against infrastructure you are
authorized to test. It requires --confirm-authorized.

Example:

  elsereno creds-check http --target https://plc-hmi.internal --confirm-authorized`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, fmt.Errorf("--target URL is required"))
			}
			if !confirmAuthorized {
				return fail(core.ExitUsage, fmt.Errorf(
					"--confirm-authorized is required: run this only against systems you are authorized to test"))
			}
			return runCredsCheckHTTP(cmd, target, timeout, jsonOut)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "device web UI URL (e.g. https://hmi.internal)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "overall check timeout")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the report as JSON")
	cmd.Flags().BoolVar(&confirmAuthorized, "confirm-authorized", false,
		"acknowledge you are authorized to test this target (required)")
	return cmd
}

func runCredsCheckHTTP(cmd *cobra.Command, target string, timeout time.Duration, jsonOut bool) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	client := &http.Client{
		Timeout: timeout,
		// Device UIs commonly present self-signed certificates; this check
		// classifies auth acceptance, it never trusts the peer.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402 -- authorized audit of the operator's own device UI
		// Do not follow redirects: a 3xx to an authenticated landing page
		// reads as acceptance, not a rejection.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	rep, err := creds.CheckHTTPBasicDefaults(ctx, client, target)
	if err != nil {
		return fail(core.ExitError, err)
	}
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	cmd.Printf("Baseline status:   %d\n", rep.BaselineStatus)
	if !rep.RequiresAuth {
		cmd.Println("The endpoint does not gate on HTTP Basic auth; no defaults to verify.")
		return nil
	}
	cmd.Printf("Credentials tried: %d\n", rep.Tested)
	if len(rep.Accepted) == 0 {
		cmd.Println("No published default credentials were accepted.")
		return nil
	}
	cmd.Printf("[!] EXPOSURE: %d published default credential(s) accepted (SP 800-82 r4 Table 13):\n", len(rep.Accepted))
	for _, c := range rep.Accepted {
		cmd.Printf("    %s:%s  (status %d, %s)\n", c.User, c.Pass, c.Status, c.Source)
	}
	return nil
}
