package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/protocols/s7"
)

// emitS7JSON writes v as indented JSON to the command's stdout.
func emitS7JSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// newS7Cmd is the verb tree for S7comm active recon (read-only).
//
//	elsereno s7 probe-protection --target plc:102
func newS7Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "s7",
		Short: "S7comm active recon (read-only): read the CPU protection level",
	}
	cmd.AddCommand(newS7ProbeCmd())
	cmd.AddCommand(newS7ProbeProtectionCmd())
	cmd.AddCommand(newS7ProbeIdentityCmd())
	return cmd
}

func newS7ProbeCmd() *cobra.Command {
	var target string
	var timeout time.Duration
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Full S7 CPU posture in one shot: identity + firmware + protection (read-only)",
		Long: `Reads a Siemens S7 CPU's full exposure posture in a single
connection: what it is (order number, firmware, module type, serial) and
whether it accepts writes/control without a password (protection level).
Combines probe-identity and probe-protection over one handshake:

  COTP CR -> Setup -> Read SZL 0x0011 -> 0x001C -> 0x0132/4

Strictly read-only. The wire is validated byte for byte against a real
captured S7-300 session.

Examples:

  elsereno s7 probe --target plc.example:102`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return errors.New("--target host:port is required")
			}
			return runS7Probe(cmd, target, timeout, jsonOut)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port of the S7 PLC (e.g. plc:102)")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "overall probe timeout")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the result as JSON")
	return cmd
}

func runS7Probe(cmd *cobra.Command, target string, timeout time.Duration, jsonOut bool) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	res, err := s7.ProbePosture(ctx, conn)
	if err != nil {
		return err
	}
	if jsonOut {
		return emitS7JSON(cmd, res)
	}
	cmd.Printf("S7/COTP server:           %t\n", res.IsS7)
	cmd.Printf("Setup Communication:      %t\n", res.SetupOK)
	if !res.SetupOK {
		return nil
	}
	cmd.Println("Identity:")
	printIdentField(cmd, "  Order number (MLFB)", res.OrderNumber)
	printIdentField(cmd, "  Firmware version", res.Firmware)
	printIdentField(cmd, "  Module type", res.ModuleType)
	printIdentField(cmd, "  Serial number", res.SerialNumber)
	printIdentField(cmd, "  Station name", res.StationName)
	printIdentField(cmd, "  Plant designation", res.PlantDesignation)
	cmd.Println("Protection:")
	if !res.ProtectionRead {
		cmd.Println("  Protection SZL:         not readable (CPU refused or does not expose it)")
		return nil
	}
	cmd.Printf("  Effective level:        %s\n", s7.ProtectionLevelText(res.Protection.RealLevel))
	cmd.Printf("  Mode selector:          %s\n", s7.ModeSelectorText(res.Protection.ModeSelector))
	if res.Exposed {
		cmd.Println("[!] EXPOSURE: the CPU enforces no read/write password (effective level 0/1). " +
			"A stranger can write tags or control the PLC, subject to the key switch.")
	}
	return nil
}

func newS7ProbeProtectionCmd() *cobra.Command {
	var target string
	var timeout time.Duration
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "probe-protection",
		Short: "Read a Siemens S7 CPU's protection level (read-only)",
		Long: `Reads a Siemens S7-300/400 CPU's protection configuration and
reports whether it accepts writes/control without a password. It drives
the S7 handshake and reads one diagnostic list:

  COTP Connection Request -> Setup Communication -> Read SZL 0x0132/4

SZL 0x0132 index 4 carries the CPU's effective (real) protection level
(1=no password, 2=write-protected, 3=read+write protected) and the mode
selector position. Effective level 1 (or 0) means a stranger can write or
control the PLC, the root misconfiguration behind "anyone can stop the
PLC / change a tag".

It is strictly read-only: it reads the protection SZL, it never writes,
controls, or stops the PLC. The wire is validated byte for byte against a
real captured S7-300 session.

Examples:

  elsereno s7 probe-protection --target plc.example:102
  elsereno s7 probe-protection --target 10.0.0.5:102 --timeout 15s`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return errors.New("--target host:port is required")
			}
			return runS7ProbeProtection(cmd, target, timeout, jsonOut)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port of the S7 PLC (e.g. plc:102)")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "overall probe timeout")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the result as JSON")
	return cmd
}

func newS7ProbeIdentityCmd() *cobra.Command {
	var target string
	var timeout time.Duration
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "probe-identity",
		Short: "Read a Siemens S7 CPU's exact model + firmware (read-only)",
		Long: `Reads a Siemens S7 CPU's identity so it can be matched against
CVEs and vendor advisories. It drives the S7 handshake and reads two
diagnostic lists:

  COTP Connection Request -> Setup Communication
    -> Read SZL 0x0011 (module identification: order number + firmware)
    -> Read SZL 0x001C (component identification: type, serial, station)

It reports the order number (MLFB, e.g. 6ES7 151-8AB01-0AB0), the firmware
version (e.g. V3.2.6), the module type name, the serial number, the station
name and the plant designation, exactly what a CVE lookup for that PLC
needs.

It is strictly read-only: it reads identity SZLs, it never writes,
controls or stops the PLC. The wire is validated byte for byte against a
real captured S7-300 session.

Examples:

  elsereno s7 probe-identity --target plc.example:102`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return errors.New("--target host:port is required")
			}
			return runS7ProbeIdentity(cmd, target, timeout, jsonOut)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port of the S7 PLC (e.g. plc:102)")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "overall probe timeout")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the result as JSON")
	return cmd
}

func runS7ProbeIdentity(cmd *cobra.Command, target string, timeout time.Duration, jsonOut bool) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	res, err := s7.ProbeIdentity(ctx, conn)
	if err != nil {
		return err
	}
	if jsonOut {
		return emitS7JSON(cmd, res)
	}
	cmd.Printf("S7/COTP server:           %t\n", res.IsS7)
	cmd.Printf("Setup Communication:      %t\n", res.SetupOK)
	if !res.SetupOK {
		return nil
	}
	printIdentField(cmd, "Order number (MLFB)", res.OrderNumber)
	printIdentField(cmd, "Firmware version", res.Firmware)
	printIdentField(cmd, "Module type", res.ModuleType)
	printIdentField(cmd, "Serial number", res.SerialNumber)
	printIdentField(cmd, "Station name", res.StationName)
	printIdentField(cmd, "Plant designation", res.PlantDesignation)
	return nil
}

func printIdentField(cmd *cobra.Command, label, value string) {
	if value == "" {
		value = "(not reported)"
	}
	cmd.Printf("%-26s%s\n", label+":", value)
}

func runS7ProbeProtection(cmd *cobra.Command, target string, timeout time.Duration, jsonOut bool) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	res, err := s7.ProbeProtection(ctx, conn)
	if err != nil {
		return err
	}
	if jsonOut {
		return emitS7JSON(cmd, res)
	}
	cmd.Printf("S7/COTP server:           %t\n", res.IsS7)
	cmd.Printf("Setup Communication:      %t\n", res.SetupOK)
	if !res.ProtectionRead {
		cmd.Println("Protection SZL:           not readable (CPU refused or does not expose it)")
		return nil
	}
	cmd.Printf("Effective protection:     %s\n", s7.ProtectionLevelText(res.Record.RealLevel))
	cmd.Printf("Parameterised level:      %s\n", s7.ProtectionLevelText(res.Record.ParamLevel))
	cmd.Printf("Key-switch level:         %s\n", s7.ProtectionLevelText(res.Record.KeySwitchLevel))
	cmd.Printf("Mode selector:            %s\n", s7.ModeSelectorText(res.Record.ModeSelector))
	if res.Exposed {
		cmd.Println("[!] EXPOSURE: the CPU enforces no read/write password (effective level 0/1). " +
			"A stranger can write tags or control the PLC, subject to the key switch.")
	}
	return nil
}
