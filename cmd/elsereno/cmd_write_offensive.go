//go:build offensive

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	mbwire "local/elsereno/internal/protocols/modbus/wire"
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
	cmd.AddCommand(newWriteSIPCmd())
	cmd.AddCommand(newWriteIAX2Cmd())
	cmd.AddCommand(newWritePBXHTTPCmd())
	cmd.AddCommand(newWriteOPCUACmd())
	cmd.AddCommand(newWriteBACnetCmd())
	return cmd
}

func newWriteModbusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "modbus",
		Short: "Modbus/TCP writes (per-request: dry-run + send; proxy session: proxy-dry-run)",
		Long: `Two modes:

- dry-run / send: per-request. Build a single Modbus PDU
  (WriteSingleCoil or WriteSingleRegister) + derive the
  per-request confirm-token. Use for one-off writes.

- proxy-dry-run: proxy-session. Derive the confirm-token for a
  gated proxy session keyed on the (unit, FC, address-range)
  allowlist the operator will later pass to
  ` + "`elsereno proxy listen --plugin modbus`" + `.
  Closes the v1.5 asymmetry where sip/iax2/pbxhttp/opcua/bacnet
  had proxy-session dry-runs but modbus only had per-request.`,
	}
	cmd.AddCommand(newWriteModbusDryRunCmd())
	cmd.AddCommand(newWriteModbusSendCmd())
	cmd.AddCommand(newWriteModbusProxyDryRunCmd())
	return cmd
}

// modbusProxyFlags groups the CLI flags for the v1.9 chunk 2
// session dry-run so the RunE body stays short (funlen).
type modbusProxyFlags struct {
	target, ppFile, emitFile string
	functions                []uint
	unit                     uint8
	addrFrom, addrTo         uint16
}

// newWriteModbusProxyDryRunCmd — v1.9 chunk 2.
// Session-level dry-run that mints the confirm-token for the
// eventual `proxy listen --plugin modbus` session. Takes a
// function-code allowlist (repeatable) + optional --unit and
// --address-from/--address-to for tighter gates.
func newWriteModbusProxyDryRunCmd() *cobra.Command {
	var f modbusProxyFlags
	cmd := &cobra.Command{
		Use:   "proxy-dry-run",
		Short: "Proxy-session dry-run — derive the confirm-token for `proxy listen --plugin modbus`",
		Long: `Takes an allowlist of function codes (and optional unit +
address range) and prints:
  - the canonical SessionMutation
  - the PayloadHash (sorted allowlist + target, SHA-256)
  - (if --vault-passphrase-file) the expected confirm-token

--emit-allow-file writes a YAML file that plugs directly into
the eventual ` + "`elsereno proxy listen --allow-file <path>`" + `.

Function codes: 5 (WriteSingleCoil), 6 (WriteSingleRegister),
15 (WriteMultipleCoils), 16 (WriteMultipleRegisters), 22
(MaskWriteRegister), 23 (ReadWriteMultipleRegisters).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWriteModbusProxyDryRun(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.target, "target", "", "upstream host:port (the Modbus/TCP device we'll proxy to)")
	cmd.Flags().UintSliceVar(&f.functions, "function", nil, "function code(s) to allow — repeatable; e.g. 6 16")
	cmd.Flags().Uint8Var(&f.unit, "unit", 0, "optional: Modbus unit identifier (0 = any)")
	cmd.Flags().Uint16Var(&f.addrFrom, "address-from", 0, "optional: inclusive start of address range")
	cmd.Flags().Uint16Var(&f.addrTo, "address-to", 0, "optional: inclusive end of address range")
	addPassphraseFileFlag(cmd, &f.ppFile)
	addEmitAllowFileFlag(cmd, &f.emitFile)
	return cmd
}

func runWriteModbusProxyDryRun(cmd *cobra.Command, f modbusProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	if len(f.functions) == 0 {
		return fail(core.ExitUsage, errors.New("--function is required (repeatable). See `--help` for FC list"))
	}
	allowed, err := buildModbusProxyAllowlist(f)
	if err != nil {
		return err
	}
	mut := modwrite.SessionMutation(f.target, allowed)
	printModbusProxySummary(cmd, f, mut)
	if err := maybeMintToken(cmd, mut, f.ppFile); err != nil {
		return err
	}
	return maybeEmitModbusProxyAllow(cmd, f)
}

func buildModbusProxyAllowlist(f modbusProxyFlags) ([]modwrite.AllowedWrite, error) {
	allowed := make([]modwrite.AllowedWrite, 0, len(f.functions))
	for _, fc := range f.functions {
		if fc > 0xFF {
			return nil, fail(core.ExitUsage, fmt.Errorf("--function %d: must be 0-255", fc))
		}
		allowed = append(allowed, modwrite.AllowedWrite{
			Unit:      f.unit, // 0 = any
			FC:        mbwire.FunctionCode(fc & 0xFF),
			StartAddr: f.addrFrom,
			EndAddr:   f.addrTo,
		})
	}
	return allowed, nil
}

func printModbusProxySummary(cmd *cobra.Command, f modbusProxyFlags, mut confirm.Mutation) {
	cmd.Printf("Protocol:     modbus\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	cmd.Printf("Functions:    %s\n", canonUintList(f.functions))
	if f.unit == 0 {
		cmd.Printf("Unit:         any (0)\n")
	} else {
		cmd.Printf("Unit:         %d\n", f.unit)
	}
	if f.addrFrom == 0 && f.addrTo == 0 {
		cmd.Printf("AddressRange: any\n")
	} else {
		cmd.Printf("AddressRange: %d..%d\n", f.addrFrom, f.addrTo)
	}
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
}

// maybeEmitModbusProxyAllow writes the YAML allow-file when
// --emit-allow-file is set. Guards against the footgun where
// --unit / --address-* tighten the gate but the YAML schema
// only stores `functions:` — emitting would silently widen the
// gate on round-trip and invalidate the confirm-token.
func maybeEmitModbusProxyAllow(cmd *cobra.Command, f modbusProxyFlags) error {
	p, err := ensureAllowFilePath(f.emitFile)
	if err != nil {
		return nil //nolint:nilerr // missing --emit-allow-file is not an error
	}
	if f.unit != 0 || f.addrFrom != 0 || f.addrTo != 0 {
		return fail(core.ExitUsage, errors.New(
			"--emit-allow-file is not compatible with --unit or --address-from/--address-to today (the YAML schema stores `functions:` only; unit + address-range round-trip is a v1.10 carry-over). "+
				"Either drop --unit/--address-* to emit a function-only YAML, or pass --unit/--address-* directly to `elsereno proxy listen` instead of using --allow-file"))
	}
	af := proxyAllowFile{
		Plugin:    pluginNameModbus,
		Target:    f.target,
		Functions: canonUints(f.functions),
	}
	return emitAllowFile(cmd, p, af)
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
