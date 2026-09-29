package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/protocols/opcua"
)

// newOPCUACmd is the verb tree for OPC UA active recon (read-only).
//
//	elsereno opcua probe-anon --target plc:4840
func newOPCUACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "opcua",
		Short: "OPC UA active recon (read-only): confirm anonymous access",
	}
	cmd.AddCommand(newOPCUAProbeAnonCmd())
	cmd.AddCommand(newOPCUAProbeWriteCmd())
	return cmd
}

func newOPCUAProbeAnonCmd() *cobra.Command {
	var target, endpoint string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "probe-anon",
		Short: "Confirm whether an anonymous OPC UA session actually opens (read-only)",
		Long: `Opens an OPC UA session as the anonymous user and reports
whether it succeeds. A SecurityMode=None endpoint only ADVERTISES
anonymous access; this actively confirms it by driving the full
handshake: HELLO -> OpenSecureChannel(None) -> GetEndpoints ->
CreateSession -> ActivateSession(Anonymous). If the final service call
returns Good, a stranger can open a session on this server.

It is read-only: it never reads or writes the address space, only proves
the session opens. (Idea from the -probe-anon check in the OT researcher
Christopher D.'s chrisdinozzi/opcua-recon.)

Examples:

  elsereno opcua probe-anon --target plc.example:4840
  elsereno opcua probe-anon --target 10.0.0.10:4840 --endpoint opc.tcp://10.0.0.10:4840`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return errors.New("--target host:port is required")
			}
			if endpoint == "" {
				endpoint = "opc.tcp://" + target
			}
			return runOPCUAProbeAnon(cmd, target, endpoint, timeout)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port of the OPC UA server (e.g. plc:4840)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "endpoint URL (default opc.tcp://<target>)")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "overall probe timeout")
	return cmd
}

func newOPCUAProbeWriteCmd() *cobra.Command {
	var target, endpoint string
	var timeout time.Duration
	var maxNodes int
	cmd := &cobra.Command{
		Use:   "probe-write",
		Short: "Walk the address space as the anonymous user and flag writeable tags (read-only)",
		Long: `Opens an anonymous OPC UA session (like probe-anon) and, if it
opens, walks the address space from ObjectsFolder (i=85) over forward
hierarchical references. For every Variable it meets it reads the
UserAccessLevel attribute and flags the ones the anonymous user can WRITE
(the AccessLevel CurrentWrite bit): the process tags a stranger could
change (a setpoint, a mode selector, an output).

It is strictly read-only: it reads the NodeClass + UserAccessLevel
attributes, it never issues a Write. The walk is breadth-first and bounded
by --max-nodes so a large or hostile address space cannot run away. (Idea
from the -probe-write check in the OT researcher Christopher D.'s
chrisdinozzi/opcua-recon.)

Examples:

  elsereno opcua probe-write --target plc.example:4840
  elsereno opcua probe-write --target 10.0.0.10:4840 --max-nodes 2000`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return errors.New("--target host:port is required")
			}
			if endpoint == "" {
				endpoint = "opc.tcp://" + target
			}
			return runOPCUAProbeWrite(cmd, target, endpoint, timeout, maxNodes)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port of the OPC UA server (e.g. plc:4840)")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "endpoint URL (default opc.tcp://<target>)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "overall probe timeout")
	cmd.Flags().IntVar(&maxNodes, "max-nodes", 500, "cap on nodes tracked / folders browsed (bounds the walk)")
	return cmd
}

func runOPCUAProbeWrite(cmd *cobra.Command, target, endpoint string, timeout time.Duration, maxNodes int) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	res, err := opcua.ProbeWriteableNodes(ctx, conn, endpoint, maxNodes)
	if err != nil {
		return err
	}
	cmd.Printf("OPC UA server:            %t\n", res.IsOPCUA)
	cmd.Printf("Anonymous session opened: %t\n", res.SessionOpened)
	if !res.SessionOpened {
		cmd.Println("No anonymous session: nothing to walk.")
		return nil
	}
	cmd.Printf("Folders browsed:          %d\n", res.FoldersBrowsed)
	cmd.Printf("Variables read:           %d\n", res.VariablesRead)
	if res.Truncated {
		cmd.Println("(walk truncated at --max-nodes; results may be incomplete)")
	}
	if len(res.Writeable) == 0 {
		cmd.Println("No anonymous-writeable tags found in the walked subtree.")
		return nil
	}
	cmd.Printf("[!] EXPOSURE: %d tag(s) writeable by the anonymous user:\n", len(res.Writeable))
	for _, w := range res.Writeable {
		cmd.Printf("    %-24s %-24s UserAccessLevel=0x%02x\n", w.NodeID, w.BrowseName, w.UserAccessLevel)
	}
	return nil
}

func runOPCUAProbeAnon(cmd *cobra.Command, target, endpoint string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	res, err := opcua.ProbeAnonymousAccess(ctx, conn, endpoint)
	if err != nil {
		return err
	}
	cmd.Printf("OPC UA server:            %t\n", res.IsOPCUA)
	cmd.Printf("Anonymous advertised:     %t (policyId %q)\n", res.AdvertisesAnonymous, res.AnonymousPolicyID)
	cmd.Printf("Anonymous session opened: %t\n", res.SessionOpened)
	if res.SessionOpened {
		cmd.Println("[!] EXPOSURE: anonymous access is confirmed. A stranger can open a session on this server.")
	}
	return nil
}
