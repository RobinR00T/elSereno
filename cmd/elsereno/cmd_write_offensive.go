//go:build offensive

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/sandbox"
	modwrite "local/elsereno/offensive/write/modbus"
)

func newWriteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "write",
		Short: "Protocol-specific write operations (offensive build)",
		Long: `Every subcommand builds the mutation payload + payload
hash + a confirm.Mutation ready for the triple-confirm wrapper.
Actual network delivery lands when the DB-backed audit writer
ships (F6+). For now, --dry-run is the only supported mode so the
operator can inspect the exact bytes that would hit the wire.`,
	}
	cmd.AddCommand(newWriteModbusCmd())
	return cmd
}

func newWriteModbusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "modbus",
		Short: "Modbus/TCP writes (dry-run default + `send` subcommand)",
	}
	cmd.AddCommand(newWriteModbusDryRunCmd())
	cmd.AddCommand(newWriteModbusSendCmd())
	return cmd
}

// buildModbusRequest is the shared flag-parsing helper for both the
// dry-run and the send variants.
func buildModbusRequest(target, op string, address, value, txID uint16, coil bool, unit uint8) (modwrite.Request, error) {
	r := modwrite.Request{
		Target:              target,
		Unit:                unit,
		TxID:                txID,
		Address:             address,
		SingleCoilValue:     coil,
		SingleRegisterValue: value,
	}
	switch op {
	case string(modwrite.OpWriteSingleCoil):
		r.Op = modwrite.OpWriteSingleCoil
	case string(modwrite.OpWriteSingleRegister):
		r.Op = modwrite.OpWriteSingleRegister
	default:
		return modwrite.Request{}, fmt.Errorf("--op must be write_single_coil or write_single_register (multi-ops land in v1.2)")
	}
	return r, nil
}

type modbusFlags struct {
	target, op           string
	address, value, txID uint16
	coil                 bool
	unit                 uint8
}

func addModbusFlags(cmd *cobra.Command, f *modbusFlags) {
	cmd.Flags().StringVar(&f.target, "target", "", "host:port")
	cmd.Flags().StringVar(&f.op, "op", "write_single_register", "write_single_coil | write_single_register")
	cmd.Flags().Uint16Var(&f.address, "address", 0, "register / coil address")
	cmd.Flags().Uint16Var(&f.value, "value", 0, "register value (for write_single_register)")
	cmd.Flags().BoolVar(&f.coil, "coil-value", false, "coil state (for write_single_coil)")
	cmd.Flags().Uint8Var(&f.unit, "unit", 1, "Modbus unit identifier")
	cmd.Flags().Uint16Var(&f.txID, "tx-id", 1, "MBAP transaction identifier")
}

func newWriteModbusDryRunCmd() *cobra.Command {
	var f modbusFlags
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print the PDU bytes + payload hash (no network I/O, no vault)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			r, err := buildModbusRequest(f.target, f.op, f.address, f.value, f.txID, f.coil, f.unit)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			frame, err := modwrite.Build(r)
			if err != nil {
				return fail(core.ExitError, err)
			}
			mut, err := modwrite.MutationFor(r)
			if err != nil {
				return fail(core.ExitError, err)
			}
			cmd.Printf("Op:          %s\n", r.Op)
			cmd.Printf("Target:      %s\n", r.Target)
			cmd.Printf("PDU bytes:   %s\n", hex.EncodeToString(frame.PDU))
			cmd.Printf("PayloadHash: %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			return nil
		},
	}
	addModbusFlags(cmd, &f)
	return cmd
}

func newWriteModbusSendCmd() *cobra.Command {
	var f modbusFlags
	var acceptWrites bool
	var confirmTarget, confirmToken, ppFile string
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Authorise + send a Modbus write (requires triple confirm + vault)",
		Long: `Real network delivery. Runs the ADR-039 triple-confirm
wrapper and, on success, sends the PDU to target and prints the
response. Every Authorize decision (allowed / denied / failed) is
appended to the audit chain at ~/.elsereno/audit.jsonl.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			if !acceptWrites {
				return fail(core.ExitUsage, errors.New("--accept-writes is required for real delivery"))
			}
			if confirmTarget == "" || confirmToken == "" {
				return fail(core.ExitUsage, errors.New("--confirm-target and --confirm-token are required"))
			}
			r, err := buildModbusRequest(f.target, f.op, f.address, f.value, f.txID, f.coil, f.unit)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			rt, err := newOffensiveRuntime(cmd, ppFile)
			if err != nil {
				return err
			}
			defer rt.Close()
			// Exploit-class profile: the modbus write path needs
			// network I/O (the whole point) but no fs-mutation or
			// spawn. ADR-042.
			if err := rt.ApplySandbox(cmd.Context(), sandbox.ProfileExploit); err != nil {
				return fail(core.ExitSoftware, fmt.Errorf("sandbox: %w", err))
			}
			c := confirm.Confirm{
				AcceptsWrites: acceptWrites,
				ConfirmTarget: confirmTarget,
				ConfirmToken:  confirmToken,
			}
			resp, err := modwrite.Execute(
				cmd.Context(), r, c, rt.Vault, rt.Auditor,
				5*time.Second, 5*time.Second,
			)
			if err != nil {
				return fail(core.ExitError, err)
			}
			cmd.Printf("sent OK — upstream responded PDU: %s\n", hex.EncodeToString(resp.PDU))
			cmd.Printf("audit row appended to: %s\n", rt.AuditPath())
			return nil
		},
	}
	addModbusFlags(cmd, &f)
	cmd.Flags().BoolVar(&acceptWrites, "accept-writes", false, "positive opt-in for real delivery (ADR-039)")
	cmd.Flags().StringVar(&confirmTarget, "confirm-target", "", "must match --target byte-for-byte")
	cmd.Flags().StringVar(&confirmToken, "confirm-token", "", "HMAC token minted during the dry-run")
	addPassphraseFileFlag(cmd, &ppFile)
	return cmd
}
