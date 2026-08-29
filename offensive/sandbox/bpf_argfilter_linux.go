//go:build offensive && linux

package sandbox

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// cloneNewMask is the OR of the CLONE_NEW* namespace-creation flags.
// Denying these on clone (while leaving the syscall otherwise allowed,
// since the Go runtime needs it for thread creation with CLONE_THREAD
// et al) closes the classic denylist gap where clone(CLONE_NEWUSER|
// CLONE_NEWNS, ...) could open a fresh namespace.
const cloneNewMask uint32 = 0x00020000 | // CLONE_NEWNS
	0x02000000 | // CLONE_NEWCGROUP
	0x04000000 | // CLONE_NEWUTS
	0x08000000 | // CLONE_NEWIPC
	0x10000000 | // CLONE_NEWUSER
	0x20000000 | // CLONE_NEWPID
	0x40000000 //  CLONE_NEWNET

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

// argRulesFor returns the arg-filter rules that should be
// installed for a given profile (v1.27 chunk 1 wire-up). The
// per-profile mapping reflects the operational needs:
//
//   - ProfileHarvest: harvest helpers emit findings to stdout
//     and never legitimately write files in the harvest
//     sandbox. Installing the openat-no-write preset prevents
//     a compromised harvest helper from dropping a file (e.g.
//     for offline exfil) without changing legitimate
//     behaviour.
//   - ProfileDial: dial subprocesses need AF_INET / AF_INET6
//     sockets to reach SIP / RTP endpoints, but they never
//     legitimately need AF_PACKET (raw L2) or AF_NETLINK
//     (kernel-config socket family). Installing the socket-
//     family preset prevents both as escape vectors.
//   - ProfileExploit: NO arg-filter preset. CVE exploits
//     legitimately need to call openat with O_CREAT (e.g. for
//     state files, output captures, dropped artefacts) and
//     the more aggressive flag list would break valid
//     exploit subprocess use-cases. The syscall-level
//     denylist remains in force.
//
// Returns the empty slice (not nil) when the profile has no
// preset assigned.
func argRulesFor(p Profile, nums syscallNums) []ArgDenyRule {
	const (
		oWronly   uint32 = 0x0001
		oRdwr     uint32 = 0x0002
		oCreat    uint32 = 0x0040
		oTrunc    uint32 = 0x0200
		oAppend   uint32 = 0x0400
		writeBits        = oWronly | oRdwr | oCreat | oTrunc | oAppend

		afPacket  uint32 = 17
		afNetlink uint32 = 16
	)
	out := []ArgDenyRule{}
	if nums.Clone != 0 {
		// clone(flags, ...): flags is arg 0. Deny namespace creation;
		// the thread-creation flags (CLONE_THREAD et al) are untouched.
		out = append(out, NewArgDenyMaskAny(nums.Clone, 0, cloneNewMask))
	}
	switch p {
	case ProfileHarvest:
		if nums.Openat != 0 {
			out = append(out, NewArgDenyMaskAny(nums.Openat, 2, writeBits))
		}
		if nums.Open != 0 {
			// open(path, flags, mode): flags is arg 1 (openat's is 2).
			out = append(out, NewArgDenyMaskAny(nums.Open, 1, writeBits))
		}
	case ProfileDial:
		if nums.Socket != 0 {
			out = append(out, NewArgDenyEqual(nums.Socket, 0, afPacket, afNetlink))
		}
	case ProfileExploit:
		// No arg-filter preset — see argRulesFor's docstring.
	case ProfileScan:
		// v2.32+: scan subprocess mirrors Harvest for the
		// write-flag denial — openat without write flags only.
		// Allows reading probe data + writing nothing on disk.
		if nums.Openat != 0 {
			out = append(out, NewArgDenyMaskAny(nums.Openat, 2, writeBits))
		}
		if nums.Open != 0 {
			out = append(out, NewArgDenyMaskAny(nums.Open, 1, writeBits))
		}
	}
	return out
}

// ArgFilterPresets returns the union of every per-profile rule
// set. Operators reaching for the full block (e.g. an audit
// printout that lists "what would the daemon block on each
// profile") use this view.
//
// The per-profile list is what `Load(profile)` installs in v1.27
// chunk 1. argRulesFor(profile, nums) returns the subset for one
// profile.
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
	if nums.Open != 0 {
		// open(pathname, flags, mode) — flags is arg 1.
		out = append(out, NewArgDenyMaskAny(nums.Open, 1, writeBits))
	}
	if nums.Socket != 0 {
		// socket(domain, type, protocol) — domain is arg 0.
		out = append(out, NewArgDenyEqual(nums.Socket, 0, afPacket, afNetlink))
	}
	if nums.Clone != 0 {
		out = append(out, NewArgDenyMaskAny(nums.Clone, 0, cloneNewMask))
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

// compiledArgSectionLen returns the number of BPF instructions the
// arg-rule section contributes to the combined filter: two per rule
// (LD nr + JEQ syscall) plus the rule body. Rules with an empty body
// (neither MaskBits nor EqualValues set) emit nothing and are skipped
// by the emitter, so they are excluded from the count too.
func compiledArgSectionLen(argRules []ArgDenyRule) int {
	total := 0
	for _, r := range argRules {
		l := ruleBodyLen(r)
		if l == 0 {
			continue
		}
		total += 2 + l
	}
	return total
}

// jumpTo returns the 8-bit forward branch offset from the instruction
// at index `from` to the instruction at index `to` (to > from). A cBPF
// branch offset counts the instructions to SKIP after the current one,
// so landing on `to` means skipping (to - from - 1). The combined
// program is far below the 255-instruction jump ceiling.
func jumpTo(to, from int) uint8 {
	return uint8(to - from - 1) // #nosec G115 -- combined program length ≪ 255
}

// compileCombinedFilter builds a SINGLE seccomp cBPF program that
// enforces both the syscall-level denylist and the per-argument
// denylist, sharing one deny tail.
//
// It replaces the earlier broken composition, where an arg-only
// program that terminated in its own RET ALLOW + RET ERRNO was
// concatenated in FRONT of the syscall program. Because seccomp
// evaluates one linear program and stops at the first RET, that made
// the whole syscall denylist unreachable (every path hit the arg
// program's RET ALLOW first) and the arg deny-jumps were off by one
// (they landed on RET ALLOW instead of RET ERRNO).
//
// Layout:
//
//	[0] LD  [arch]
//	[1] JEQ auditArch, +1, 0        (arch mismatch -> KILL)
//	[2] RET KILL
//	[3] LD  [nr]
//	    -- syscall denylist: one JEQ per blocked nr, each Jt -> RET ERRNO --
//	    -- arg-rule blocks: reload nr, JEQ syscall, then the arg body.
//	       Each deny branch jumps to the shared RET ERRNO; each allow
//	       branch falls through to the next block / RET ALLOW. --
//	[M]   RET ALLOW
//	[M+1] RET ERRNO|EPERM
//
// Every deny jump is computed from the instruction's own index to the
// final RET ERRNO index, so a rule that fires always lands on RET
// ERRNO and never on RET ALLOW. With argRules empty this is byte-for-
// byte the same program compileFilter produces.
func compileCombinedFilter(auditArch uint32, blocked []uint32, argRules []ArgDenyRule) []unix.SockFilter {
	argLen := compiledArgSectionLen(argRules)
	// 4 prefix (LD arch, JEQ arch, RET KILL, LD nr) + denylist +
	// arg section + 2 tail (RET ALLOW, RET ERRNO).
	total := 4 + len(blocked) + argLen + 2
	retErrnoIdx := total - 1

	insns := make([]unix.SockFilter, 0, total)

	// [0] LD [arch]; [1] JEQ arch (match -> skip KILL); [2] RET KILL.
	insns = append(insns, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompDataOffsetArch})
	insns = append(insns, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	insns = append(insns, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetKill})
	// [3] LD [nr].
	insns = append(insns, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompDataOffsetNR})

	// Syscall denylist: each JEQ jumps forward to RET ERRNO on match,
	// falls through to the next check on miss.
	for i, nr := range blocked {
		idx := 4 + i
		insns = append(insns, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpTo(retErrnoIdx, idx),
			Jf:   0,
			K:    nr,
		})
	}

	// Arg-rule blocks. A syscall that survived the denylist is
	// re-loaded (the arg bodies clobber the accumulator with the
	// argument value) and matched against each rule's syscall number.
	for _, r := range argRules {
		l := ruleBodyLen(r)
		if l == 0 {
			continue
		}
		// LD [nr]; JEQ syscall (match -> fall into body, miss -> skip body).
		insns = append(insns, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompDataOffsetNR})
		insns = append(insns, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   0,
			Jf:   uint8(l), // #nosec G115 -- l == ruleBodyLen(r) ≤ 6
			K:    r.Syscall,
		})
		insns = append(insns, emitCombinedRuleBody(r, len(insns), retErrnoIdx)...)
	}

	// Tail: RET ALLOW then RET ERRNO|EPERM.
	insns = append(insns, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})
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

// emitCombinedRuleBody emits the body of one arg rule for the combined
// program. bodyStart is the absolute index the body's first
// instruction will occupy; retErrnoIdx is the shared deny target.
// Deny branches jump to retErrnoIdx; allow branches fall through to the
// next block (or, after the last rule, to RET ALLOW).
func emitCombinedRuleBody(r ArgDenyRule, bodyStart, retErrnoIdx int) []unix.SockFilter {
	out := make([]unix.SockFilter, 0, ruleBodyLen(r))
	if r.MaskBits != 0 {
		// LD [arg]; AND mask; JEQ 0.
		out = append(out, unix.SockFilter{
			Code: bpfLD | bpfW | bpfABS,
			K:    seccompDataArgOffset(r.ArgIndex),
		})
		// AND mask  ->  BPF_ALU|BPF_AND. Not in the local opcode
		// constants; declare them inline.
		const bpfALU uint16 = 0x04
		const bpfAND uint16 = 0x50
		out = append(out, unix.SockFilter{
			Code: bpfALU | bpfAND | bpfK,
			K:    r.MaskBits,
		})
		// JEQ 0 — (arg & mask) == 0 falls through (allow); != 0 jumps
		// to the shared RET ERRNO (deny).
		jeqIdx := bodyStart + 2
		out = append(out, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   0,
			Jf:   jumpTo(retErrnoIdx, jeqIdx),
			K:    0,
		})
		return out
	}
	// Equal-mode body: LD [arg] + N × JEQ value. Any match jumps to
	// deny; a miss falls through to the next JEQ, and past the last
	// one to the next block (allow).
	out = append(out, unix.SockFilter{
		Code: bpfLD | bpfW | bpfABS,
		K:    seccompDataArgOffset(r.ArgIndex),
	})
	for k, v := range r.EqualValues {
		jeqIdx := bodyStart + 1 + k
		out = append(out, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jumpTo(retErrnoIdx, jeqIdx),
			Jf:   0,
			K:    v,
		})
	}
	return out
}

// CompileFilterWithArgs builds a single seccomp BPF program that
// enforces the syscall-level denylist AND the per-argument denylist:
//
//   - Returns ALLOW to syscalls not in the denylist AND not matching
//     any arg-deny rule.
//   - Returns ERRNO|EPERM to anything that fires either layer.
//   - Returns KILL to a mismatched architecture (checked first).
//
// Architectures: same as FilterProgram (amd64 + arm64). On other
// arches, returns ErrArchUnsupported so Load falls back to the
// NO_NEW_PRIVS-only degraded mode.
func CompileFilterWithArgs(p Profile, argRules []ArgDenyRule) ([]unix.SockFilter, error) {
	if !p.Valid() {
		return nil, fmt.Errorf("sandbox: unknown profile %q", p)
	}
	arch, nums, err := archFor(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	blocked := blockedSyscalls(p, nums)
	if len(argRules) == 0 {
		// No arg rules: the combined builder would produce the same
		// program compileFilter does, but call it directly to keep
		// the no-args path identical to FilterProgram.
		return compileFilter(arch, blocked), nil
	}
	return compileCombinedFilter(arch, blocked, argRules), nil
}
