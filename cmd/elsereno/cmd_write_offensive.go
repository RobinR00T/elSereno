//go:build offensive

package main

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
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
	var target string
	var op string
	var address uint16
	var value uint16
	var coil bool
	var unit uint8
	var txID uint16
	cmd := &cobra.Command{
		Use:   "modbus",
		Short: "Dry-run a Modbus/TCP write (prints PDU bytes + payload hash)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
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
				return fail(core.ExitUsage, fmt.Errorf("--op must be write_single_coil or write_single_register (multi-ops: see write_multi*)"))
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
			cmd.Println()
			cmd.Println("Next: derive the confirm token against your unlocked vault (F6+ CLI).")
			cmd.Println("Operators reviewing this output should verify the PDU bytes match their intent before committing.")
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port")
	cmd.Flags().StringVar(&op, "op", "write_single_register", "write_single_coil | write_single_register")
	cmd.Flags().Uint16Var(&address, "address", 0, "register / coil address")
	cmd.Flags().Uint16Var(&value, "value", 0, "register value (for write_single_register)")
	cmd.Flags().BoolVar(&coil, "coil-value", false, "coil state (for write_single_coil)")
	cmd.Flags().Uint8Var(&unit, "unit", 1, "Modbus unit identifier")
	cmd.Flags().Uint16Var(&txID, "tx-id", 1, "MBAP transaction identifier")
	return cmd
}
