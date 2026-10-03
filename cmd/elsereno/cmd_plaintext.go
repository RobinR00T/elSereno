package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/exposure"
)

// newPlaintextCheckCmd is the top-level verb for the cleartext-transport
// exposure check (NIST SP 800-82 r4 Table 16).
func newPlaintextCheckCmd() *cobra.Command {
	var target string
	var timeout time.Duration
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "plaintext-check",
		Short: "Check whether a service's transport is cleartext (read-only)",
		Long: `Determines whether a reachable service carries its traffic in
plaintext by actively testing whether it negotiates TLS. A service that is
reachable but does not complete a TLS handshake is flagged as cleartext.

This evidences NIST SP 800-82 Rev. 4 Table 16, "Standard, well-documented
communication protocols are used in plaintext" and "Use of unsecure OT
protocols" (see docs/standards/nist-sp800-82r4.md). For well-known ports it
also names the protocol and, for IT protocols, the encrypted alternative
(http -> https, telnet -> ssh, ...); OT protocols (Modbus, S7, ...) are
cleartext by design and the mitigation is network segmentation.

When the service does negotiate TLS, this also reports its TLS posture:
whether it still accepts the deprecated TLS 1.0 / 1.1 versions (each
confirmed with a version-pinned handshake) and whether its certificate
has expired. A weak posture evidences the same Table 16 "substandard"
authentication / encryption condition.

It is read-only: it opens connections and attempts TLS handshakes,
nothing more.

Examples:

  elsereno plaintext-check --target plc.example:502
  elsereno plaintext-check --target 10.0.0.5:80 --json
  elsereno plaintext-check --target 10.0.0.5:443   # reports TLS posture`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return errors.New("--target host:port is required")
			}
			return runPlaintextCheck(cmd, target, timeout, jsonOut)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port to check (e.g. plc:502)")
	cmd.Flags().DurationVar(&timeout, "timeout", 8*time.Second, "overall check timeout")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the result as JSON")
	return cmd
}

func runPlaintextCheck(cmd *cobra.Command, target string, timeout time.Duration, jsonOut bool) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	res, err := exposure.ProbeCleartext(ctx, target, timeout)
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	cmd.Printf("Reachable:   %t\n", res.Reachable)
	if !res.Reachable {
		return nil
	}
	if res.Protocol != "" {
		cmd.Printf("Protocol:    %s\n", res.Protocol)
	}
	if res.TLS {
		cmd.Printf("Transport:   TLS (%s)\n", res.TLSVersion)
		if res.CertNotAfter != "" {
			status := "valid"
			if res.CertExpired {
				status = "EXPIRED"
			}
			cmd.Printf("Certificate: %s (NotAfter %s)\n", status, res.CertNotAfter)
		}
		if len(res.DeprecatedTLS) > 0 {
			cmd.Printf("Deprecated:  still accepts %s\n", strings.Join(res.DeprecatedTLS, ", "))
		}
		if res.WeakTLS {
			var parts []string
			if len(res.DeprecatedTLS) > 0 {
				parts = append(parts, "accepts deprecated "+strings.Join(res.DeprecatedTLS, "/"))
			}
			if res.CertExpired {
				parts = append(parts, "certificate expired")
			}
			cmd.Printf("[!] EXPOSURE: weak TLS posture (%s) (SP 800-82 r4 Table 16).\n", strings.Join(parts, "; "))
		}
		return nil
	}
	cmd.Println("Transport:   cleartext (no TLS)")
	msg := "[!] EXPOSURE: this service carries its traffic in plaintext (SP 800-82 r4 Table 16)."
	if res.SecureAlternative != "" {
		msg += " Encrypted alternative: " + res.SecureAlternative + "."
	} else if res.Protocol != "" {
		msg += " OT protocol with no in-protocol encryption; mitigate with network segmentation."
	}
	cmd.Println(msg)
	return nil
}
