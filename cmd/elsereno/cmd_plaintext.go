package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/exposure"
	"local/elsereno/internal/standards"
)

// newPlaintextCheckCmd is the top-level verb for the cleartext-transport
// exposure check (NIST SP 800-82 r4 Table 16).
func newPlaintextCheckCmd() *cobra.Command {
	var v targetVerb
	var listPorts bool
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

Remote-administration, database and directory services (SSH, RDP, VNC,
SMB, MS SQL, Kerberos, ...) are reported as IT management services, never
as cleartext: their encryption is not a TLS handshake on connect, and
their presence on an OT segment is the finding. A UDP-only port (BACnet,
SNMP, TriStation, PROFINET CM) is named but not dialled, because this
check is TCP.

--list-ports prints the port catalogue (port, transport, category,
protocol, secure alternative, note) and exits without connecting.

It is read-only: it opens connections and attempts TLS handshakes,
nothing more.

Examples:

  elsereno plaintext-check --target plc.example:502
  elsereno plaintext-check --target 10.0.0.5:80 --json
  elsereno plaintext-check --target 10.0.0.5:443   # reports TLS posture
  elsereno plaintext-check --target 10.0.0.5:3389  # IT management service
  elsereno plaintext-check --list-ports`,
	}
	scoped := v.runE("", runPlaintextCheck)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if listPorts {
			return printPortCatalogue(c, v.jsonOut)
		}
		return scoped(c, args)
	}
	v.register(cmd, "host:port to check (e.g. plc:502)", 8*time.Second, "overall check timeout")
	cmd.Flags().BoolVar(&listPorts, "list-ports", false, "print the well-known port catalogue and exit (no connection)")
	return cmd
}

// printPortCatalogue renders exposure.Ports as a table or JSON.
func printPortCatalogue(cmd *cobra.Command, jsonOut bool) error {
	ports := exposure.Ports()
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(ports)
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PORT\tCATEGORY\tPROTOCOL\tSECURE ALTERNATIVE\tNOTE")
	for _, e := range ports {
		_, _ = fmt.Fprintf(tw, "%d/%s\t%s\t%s\t%s\t%s\n", e.Port, e.Transport, e.Category, e.Protocol, e.SecureAlternative, e.Note)
	}
	return tw.Flush()
}

// printTLSPosture reports the TLS version, certificate state and any
// weak-TLS exposure for a service that negotiated TLS.
func printTLSPosture(cmd *cobra.Command, res exposure.TransportResult) {
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
	if res.Transport == exposure.TransportUDP {
		cmd.Printf("Protocol:    %s (UDP)\n", res.Protocol)
		cmd.Println("Reachable:   not checked: UDP service, this check is TCP; use the protocol's plugin or verb")
		printNote(cmd, res.Note)
		return nil
	}
	cmd.Printf("Reachable:   %t\n", res.Reachable)
	if !res.Reachable {
		return nil
	}
	if res.Protocol != "" {
		cmd.Printf("Protocol:    %s (%s)\n", res.Protocol, res.Category)
	}
	if res.ITManagement {
		cmd.Println("[!] EXPOSURE: IT management service reachable. On an OT segment it is a path from IT into the plant; restrict it to a jump host.")
		printNote(cmd, res.Note)
		for _, r := range standards.ForProtocol("it-management") {
			cmd.Printf("Standard:    %s %s: %s\n", r.Standard, r.Table, r.Vuln)
		}
		return nil
	}
	if res.Category == exposure.CategoryITCleartext || res.Category == exposure.CategoryITEncrypted {
		defer printNote(cmd, res.Note)
	}
	if res.TLS {
		printTLSPosture(cmd, res)
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

// printNote prints the catalogue hint for the port, when there is one.
func printNote(cmd *cobra.Command, note string) {
	if note != "" {
		cmd.Printf("Note:        %s\n", note)
	}
}
