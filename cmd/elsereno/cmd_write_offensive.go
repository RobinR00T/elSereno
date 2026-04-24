//go:build offensive

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/sandbox"
	modwrite "local/elsereno/offensive/write/modbus"
)

// parseModbusWriteFlag parses a --write value in the form
// `unit=N;fc=M;start=A;end=B` into an AllowedWrite. `fc` is
// required; `unit` / `start` / `end` default to 0 (any).
// Spaces around tokens are tolerated.
func parseModbusWriteFlag(s string) (modwrite.AllowedWrite, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return modwrite.AllowedWrite{}, fmt.Errorf("--write %q: empty", s)
	}
	var out modwrite.AllowedWrite
	var fcSeen bool
	for _, p := range strings.Split(raw, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key, n, err := splitModbusWriteToken(s, p)
		if err != nil {
			return modwrite.AllowedWrite{}, err
		}
		if err := applyModbusWriteKey(s, key, n, &out, &fcSeen); err != nil {
			return modwrite.AllowedWrite{}, err
		}
	}
	if !fcSeen {
		return modwrite.AllowedWrite{}, fmt.Errorf("--write %q: fc= is required", s)
	}
	if out.StartAddr > out.EndAddr && out.EndAddr != 0 {
		return modwrite.AllowedWrite{}, fmt.Errorf("--write %q: start=%d > end=%d", s, out.StartAddr, out.EndAddr)
	}
	return out, nil
}

// splitModbusWriteToken validates one KEY=VALUE pair and returns
// (lowercase-key, numeric-value).
func splitModbusWriteToken(orig, p string) (string, uint64, error) {
	kv := strings.SplitN(p, "=", 2)
	if len(kv) != 2 {
		return "", 0, fmt.Errorf("--write %q: each token is KEY=VALUE", orig)
	}
	key := strings.ToLower(strings.TrimSpace(kv[0]))
	val := strings.TrimSpace(kv[1])
	n, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return "", 0, fmt.Errorf("--write %q: %s %q is not a number", orig, key, val)
	}
	return key, n, nil
}

// applyModbusWriteKey folds one parsed KEY=VALUE into the
// destination AllowedWrite. Also updates fcSeen when key==fc so
// the caller can enforce the required-field check.
func applyModbusWriteKey(orig, key string, n uint64, out *modwrite.AllowedWrite, fcSeen *bool) error {
	switch key {
	case "unit":
		if n > 0xFF {
			return fmt.Errorf("--write %q: unit must fit in uint8", orig)
		}
		out.Unit = uint8(n & 0xFF)
	case "fc":
		if n == 0 || n > 0xFF {
			return fmt.Errorf("--write %q: fc must be 1-255", orig)
		}
		out.FC = mbwire.FunctionCode(n & 0xFF)
		*fcSeen = true
	case "start":
		if n > 0xFFFF {
			return fmt.Errorf("--write %q: start must fit in uint16", orig)
		}
		out.StartAddr = uint16(n & 0xFFFF)
	case "end":
		if n > 0xFFFF {
			return fmt.Errorf("--write %q: end must fit in uint16", orig)
		}
		out.EndAddr = uint16(n & 0xFFFF)
	default:
		return fmt.Errorf("--write %q: unknown key %q (expected unit, fc, start, or end)", orig, key)
	}
	return nil
}

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
	cmd.AddCommand(newWriteCWMPCmd())
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
// session dry-run so the RunE body stays short (funlen). v1.12
// chunk 4 adds writes: repeated --write flag for structured
// (unit, FC, address-range) entries that round-trip through YAML.
type modbusProxyFlags struct {
	target, ppFile, emitFile string
	functions                []uint
	unit                     uint8
	addrFrom, addrTo         uint16
	writes                   []string // v1.12+: structured "unit=N;fc=M;start=A;end=B"
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
	cmd.Flags().UintSliceVar(&f.functions, "function", nil, "function code(s) to allow — repeatable; e.g. 6 16 (legacy; pairs with --unit/--address-from/--address-to to produce one allow-entry shared by every FC)")
	cmd.Flags().Uint8Var(&f.unit, "unit", 0, "optional: Modbus unit identifier (0 = any)")
	cmd.Flags().Uint16Var(&f.addrFrom, "address-from", 0, "optional: inclusive start of address range")
	cmd.Flags().Uint16Var(&f.addrTo, "address-to", 0, "optional: inclusive end of address range")
	cmd.Flags().StringSliceVar(&f.writes, "write", nil, "v1.12+: structured per-entry allowlist unit=N;fc=M;start=A;end=B (repeatable). fc= is required; unit/start/end default to 0 (any). Round-trips through --emit-allow-file.")
	addPassphraseFileFlag(cmd, &f.ppFile)
	addEmitAllowFileFlag(cmd, &f.emitFile)
	return cmd
}

func runWriteModbusProxyDryRun(cmd *cobra.Command, f modbusProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	if len(f.functions) == 0 && len(f.writes) == 0 {
		return fail(core.ExitUsage, errors.New("--function or --write is required (repeatable). See `--help` for FC list"))
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
	allowed := make([]modwrite.AllowedWrite, 0, len(f.functions)+len(f.writes))
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
	for _, raw := range f.writes {
		w, err := parseModbusWriteFlag(raw)
		if err != nil {
			return nil, fail(core.ExitUsage, err)
		}
		allowed = append(allowed, w)
	}
	return allowed, nil
}

func printModbusProxySummary(cmd *cobra.Command, f modbusProxyFlags, mut confirm.Mutation) {
	cmd.Printf("Protocol:     modbus\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	if len(f.functions) > 0 {
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
	}
	if len(f.writes) > 0 {
		cmd.Printf("Writes:       %d structured entries\n", len(f.writes))
		for _, raw := range f.writes {
			cmd.Printf("  - %s\n", raw)
		}
	}
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
}

// maybeEmitModbusProxyAllow writes the YAML allow-file when
// --emit-allow-file is set. v1.12 chunk 4 closes the v1.9 carry-
// over: structured --write entries round-trip cleanly through
// the new `writes:` YAML field, so the guard against --unit /
// --address-* + emit is lifted — those legacy flags now
// materialise as a single `writes:` entry in the emitted file.
func maybeEmitModbusProxyAllow(cmd *cobra.Command, f modbusProxyFlags) error {
	p, err := ensureAllowFilePath(f.emitFile)
	if err != nil {
		return nil //nolint:nilerr // missing --emit-allow-file is not an error
	}
	af := buildAllowFileModbus(f)
	return emitAllowFile(cmd, p, af)
}

// buildAllowFileModbus emits the modbus allow-file. Legacy
// --function + --unit + --address-* combinations collapse into
// one `writes:` entry per FC. Structured --write entries pass
// through verbatim.
func buildAllowFileModbus(f modbusProxyFlags) proxyAllowFile {
	af := proxyAllowFile{
		Plugin: pluginNameModbus,
		Target: f.target,
	}
	// Legacy path: if --unit/--address-* are default, still keep
	// the compact `functions:` shape (preserves v1.9 YAML form).
	// Otherwise lift each FC into a structured writes: entry so
	// the gate tightening survives the round-trip.
	legacyIsPlain := f.unit == 0 && f.addrFrom == 0 && f.addrTo == 0
	if legacyIsPlain && len(f.functions) > 0 {
		af.Functions = canonUints(f.functions)
	} else {
		for _, fc := range f.functions {
			af.Writes = append(af.Writes, proxyModbusWrite{
				Unit:  f.unit,
				FC:    uint8(fc & 0xFF),
				Start: f.addrFrom,
				End:   f.addrTo,
			})
		}
	}
	// Structured --write entries round-trip verbatim.
	for _, raw := range f.writes {
		w, err := parseModbusWriteFlag(raw)
		if err != nil {
			// Upstream pre-check already validated; skip silently.
			continue
		}
		af.Writes = append(af.Writes, proxyModbusWrite{
			Unit:  w.Unit,
			FC:    uint8(w.FC),
			Start: w.StartAddr,
			End:   w.EndAddr,
		})
	}
	// Sort `writes:` for determinism (by unit, fc, start, end).
	if len(af.Writes) > 0 {
		sortProxyModbusWrites(af.Writes)
	}
	return af
}

// sortProxyModbusWrites orders entries by (unit, fc, start, end)
// so round-trip emission is stable. Mirrors the library's
// AllowlistHash sort order.
func sortProxyModbusWrites(w []proxyModbusWrite) {
	sort.Slice(w, func(i, j int) bool {
		if w[i].Unit != w[j].Unit {
			return w[i].Unit < w[j].Unit
		}
		if w[i].FC != w[j].FC {
			return w[i].FC < w[j].FC
		}
		if w[i].Start != w[j].Start {
			return w[i].Start < w[j].Start
		}
		return w[i].End < w[j].End
	})
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
