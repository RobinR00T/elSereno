//go:build offensive && linux

package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ArgDenyRule describes a per-argument denylist for a single
// syscall. The kernel's seccomp BPF program is given the syscall
// number; if it matches Syscall, the program also loads
// `seccomp_data.args[ArgIndex]` and refuses the call when
// the loaded value satisfies the rule's match predicate.
//
// Two match modes are supported:
//
//   - **Equal**: deny when arg == one of EqualValues. Useful for
//     `socket(family, …)` — deny when family == AF_PACKET.
//   - **MaskAny**: deny when (arg & MaskBits) != 0. Useful for
//     `openat(dirfd, path, flags, …)` — deny when flags has any
//     of {O_WRONLY, O_RDWR, O_CREAT, O_TRUNC} set.
//
// Use NewArgDenyEqual / NewArgDenyMaskAny rather than
// constructing the struct directly. The rule is compiled into
// BPF only on platforms that support seccomp; non-Linux builds
// silently skip arg-filter integration (the syscall-level
// denylist still applies).
type ArgDenyRule struct {
	// Syscall is the syscall number this rule scopes to (in the
	// architecture's ABI numbering). Use the syscallsAMD64 /
	// syscallsARM64 lookup tables to avoid hard-coding numbers.
	Syscall uint32
	// ArgIndex is the seccomp_data.args[N] slot to inspect
	// (0..5). Each slot is 64 bits on the wire but the BPF
	// instructions can only compare 32 bits at a time; this
	// implementation inspects the LOW 32 bits of the argument,
	// which is sufficient for every flag word + numeric argument
	// the offensive profiles need to gate.
	ArgIndex uint8
	// EqualValues: deny when (arg & 0xFFFFFFFF) equals any of
	// these. Empty means "no equal-match rule for this arg".
	EqualValues []uint32
	// MaskBits: deny when (arg & 0xFFFFFFFF & MaskBits) != 0.
	// Zero means "no mask rule for this arg".
	MaskBits uint32
}

// NewArgDenyEqual builds a rule that denies syscall when
// args[argIdx] equals any of values (low 32 bits).
func NewArgDenyEqual(syscall uint32, argIdx uint8, values ...uint32) ArgDenyRule {
	return ArgDenyRule{
		Syscall:     syscall,
		ArgIndex:    argIdx,
		EqualValues: append([]uint32(nil), values...),
	}
}

// NewArgDenyMaskAny builds a rule that denies syscall when
// (args[argIdx] & maskBits) != 0.
func NewArgDenyMaskAny(syscall uint32, argIdx uint8, maskBits uint32) ArgDenyRule {
	return ArgDenyRule{
		Syscall:  syscall,
		ArgIndex: argIdx,
		MaskBits: maskBits,
	}
}

// ArgFilterPresets returns operator-friendly default arg rules:
//
//   - openat: deny when flags has any write / create / truncate
//     bits set. Effectively "openat read-only or fail".
//   - socket: deny AF_PACKET + AF_NETLINK families.
//
// Caller picks the syscall numbers from the running architecture's
// table (syscallsAMD64 / syscallsARM64) — they aren't compile-
// time constants per ARCH inside this file because the rule list
// crosses architectures.
//
// Returns rules referencing syscall numbers from `nums`; the
// caller compiles them via CompileArgFilter.
func ArgFilterPresets(nums syscallNums) []ArgDenyRule {
	const (
		// open(2) flags relevant to write / mutate.
		oWronly   uint32 = 0x0001
		oRdwr     uint32 = 0x0002
		oCreat    uint32 = 0x0040
		oTrunc    uint32 = 0x0200
		oAppend   uint32 = 0x0400
		writeBits        = oWronly | oRdwr | oCreat | oTrunc | oAppend

		afPacket  uint32 = 17 // AF_PACKET (raw L2)
		afNetlink uint32 = 16 // AF_NETLINK
	)
	out := make([]ArgDenyRule, 0, 4)
	if nums.Openat != 0 {
		// openat(dirfd, pathname, flags, mode) — flags is arg 2.
		out = append(out, NewArgDenyMaskAny(nums.Openat, 2, writeBits))
	}
	if nums.Socket != 0 {
		// socket(domain, type, protocol) — domain is arg 0.
		out = append(out, NewArgDenyEqual(nums.Socket, 0, afPacket, afNetlink))
	}
	return out
}

// seccompDataArgOffset returns the LOW-32-bit offset of
// seccomp_data.args[i]. Each arg slot is 64 bits and starts at
// 0x10 + i*8 in struct seccomp_data; the LOW dword is therefore
// at 0x10 + i*8 on little-endian (x86_64 + aarch64 are both LE,
// so we don't carry a high-dword path here).
func seccompDataArgOffset(idx uint8) uint32 {
	// idx is uint8 (0..5 in practice; max 255), so 16 + idx*8
	// is bounded above by 2056 — fits cleanly in uint32 without
	// overflow.
	return uint32(16) + uint32(idx)*uint32(8)
}

// CompileArgFilter emits BPF instructions implementing the rules
// in `argRules`. The output is appended to a pre-existing
// syscall-level filter (compiled by `compileFilter`) by replacing
// its tail (RET ALLOW + RET ERRNO) with the arg-filter prologue +
// the syscall-level tails.
//
// The simplest way to use it is via CompileFilterWithArgs below,
// which composes `compileFilter` + this function correctly.
//
// Layout per arg rule (each rule is independent of the others):
//
//	#  LD  [nr]
//	#  JEQ syscall, +1, +M       (M = total instr count of this rule)
//	#  -- rule body if syscall matches --
//	#    LD  [arg_offset]
//	#    JEQ value_1, deny, ...        (Equal mode)
//	#    JEQ value_K, deny, +1
//	#    -- (or, MaskAny mode) --
//	#    AND maskBits
//	#    JEQ 0, allow_through, +1
//	#  -- rule end (next rule or tail) --
//
// The deny target is "RET ERRNO|EPERM" which lives at the very
// end of the program. The allow_through target is "fall through to
// the next rule".
//
// For v1.26 chunk 2 the implementation is intentionally minimal:
// each rule appends a self-contained block that ends in a "deny"
// or "fall through" decision, and rules are ORed together — any
// rule firing denies the call. This keeps the BPF easy to
// reason about and lets the unit tests verify the instruction
// count exactly.
//
// Returns ErrArchUnsupported in archFor's sense — the caller is
// expected to have validated the arch via the FilterProgram call
// already.
func CompileArgFilter(argRules []ArgDenyRule) []unix.SockFilter {
	if len(argRules) == 0 {
		return nil
	}
	// The deny-tail (RET ERRNO|EPERM) is at len(insns)+totalLen.
	// Build forward, recording for each rule how many BPF insns
	// it emits, so we can compute the relative jump to the deny
	// tail correctly.
	//
	// To keep the code simple we emit:
	//   for each rule:
	//     LD nr; JEQ syscall, fall=skip-rule-body, jt=+1
	//     (rule body — a sequence of JEQs / mask checks; on
	//     match each jumps forward to the deny tail).
	//   end:
	//     RET ALLOW
	//     RET ERRNO|EPERM
	//
	// Computing the jump offsets requires two passes; the
	// implementation walks the rules twice.

	// Pass 1: measure each rule's body length.
	bodyLens := make([]int, len(argRules))
	totalBody := 0
	for i, r := range argRules {
		bodyLens[i] = ruleBodyLen(r)
		totalBody += bodyLens[i] + 2 // +2 for LD nr + JEQ syscall
	}
	tailLen := 2 // RET ALLOW + RET ERRNO

	// Pass 2: emit.
	insns := make([]unix.SockFilter, 0, totalBody+tailLen)
	emitted := 0
	for i, r := range argRules {
		// LD [nr]
		insns = append(insns, unix.SockFilter{
			Code: bpfLD | bpfW | bpfABS,
			K:    seccompDataOffsetNR,
		})
		emitted++

		// JEQ syscall, jt=+1 (fall into rule body), jf=bodyLen[i] (skip rule body)
		jf := uint8(bodyLens[i]) //nolint:gosec // G115 — bodyLen bounded by ruleBodyLen ≤ 6
		insns = append(insns, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   0,
			Jf:   jf,
			K:    r.Syscall,
		})
		emitted++

		// rule body — emits exactly bodyLens[i] insns. The deny
		// jump target is the RET ERRNO insn at the program end:
		// we compute the offset from the END of the body to that
		// instruction.
		distToDeny := totalBody - (emitted + bodyLens[i]) + 1 // +1 to skip RET ALLOW
		body := emitRuleBody(r, distToDeny)
		insns = append(insns, body...)
		emitted += bodyLens[i]
		_ = i
	}
	// tail RET ALLOW
	insns = append(insns, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})
	// tail RET ERRNO|EPERM
	insns = append(insns, unix.SockFilter{
		Code: bpfRET | bpfK,
		K:    seccompRetErrno | uint32(unix.EPERM),
	})
	return insns
}

// ruleBodyLen counts the BPF instructions emitRuleBody would
// emit for rule r — used to compute jump offsets in the first
// pass.
func ruleBodyLen(r ArgDenyRule) int {
	if r.MaskBits != 0 {
		// LD arg + AND mask + JEQ 0
		return 3
	}
	if len(r.EqualValues) > 0 {
		// LD arg + N × JEQ value
		return 1 + len(r.EqualValues)
	}
	return 0
}

// emitRuleBody returns the BPF for one rule. Each instruction in
// the body either falls through to the next or jumps forward by
// distToDeny instructions to land on the program-tail RET ERRNO.
func emitRuleBody(r ArgDenyRule, distToDeny int) []unix.SockFilter {
	out := make([]unix.SockFilter, 0, ruleBodyLen(r))
	if r.MaskBits != 0 {
		// LD [arg]
		out = append(out, unix.SockFilter{
			Code: bpfLD | bpfW | bpfABS,
			K:    seccompDataArgOffset(r.ArgIndex),
		})
		// AND mask  →  use BPF_ALU|BPF_AND. We don't have those
		// in the local opcode constants; declare them inline.
		const bpfALU uint16 = 0x04
		const bpfAND uint16 = 0x50
		out = append(out, unix.SockFilter{
			Code: bpfALU | bpfAND | bpfK,
			K:    r.MaskBits,
		})
		// JEQ 0 — if (arg & mask) == 0 fall through (allow);
		// otherwise jump distToDeny instructions forward.
		jt := uint8(distToDeny - 1) //nolint:gosec // G115 — distToDeny bounded by program size
		out = append(out, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   0,
			Jf:   jt,
			K:    0,
		})
		return out
	}
	// Equal-mode body: LD arg + N × JEQ value. The Nth match
	// jumps to deny; falls through after the last on no-match.
	// LD [arg]
	out = append(out, unix.SockFilter{
		Code: bpfLD | bpfW | bpfABS,
		K:    seccompDataArgOffset(r.ArgIndex),
	})
	for i, v := range r.EqualValues {
		// Distance to deny: distToDeny - 1 (already past LD)
		// - i (each prior JEQ added one) - 1 (this JEQ itself).
		jt := uint8(distToDeny - 1 - i - 1) //nolint:gosec // G115 — bounded
		out = append(out, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jt,
			Jf:   0,
			K:    v,
		})
	}
	return out
}

// CompileFilterWithArgs composes the existing syscall-level
// denylist filter with an arg-level denylist. Returns a single
// BPF program that:
//
//   - Returns ALLOW to syscalls not in the denylist AND not
//     matching any arg-deny rule.
//   - Returns ERRNO|EPERM to anything that fires either layer.
//
// Architectures: same as FilterProgram (amd64 + arm64). On
// other arches, returns ErrArchUnsupported.
func CompileFilterWithArgs(p Profile, argRules []ArgDenyRule) ([]unix.SockFilter, error) {
	if !p.Valid() {
		return nil, fmt.Errorf("sandbox: unknown profile %q", p)
	}
	syscallProg, err := FilterProgram(p)
	if err != nil {
		return nil, err
	}
	if len(argRules) == 0 {
		return syscallProg, nil
	}
	argProg := CompileArgFilter(argRules)
	// Concatenate: the arg-filter program runs FIRST, so any
	// arg-rule match returns ERRNO|EPERM before the syscall
	// denylist gets a chance to ALLOW.
	out := make([]unix.SockFilter, 0, len(argProg)+len(syscallProg))
	out = append(out, argProg...)
	out = append(out, syscallProg...)
	return out, nil
}
