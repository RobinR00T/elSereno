//go:build offensive && linux

package sandbox

// syscallNums enumerates every syscall name the sandbox
// denylists use. The underlying type is uint32 (matches BPF's K
// field and the seccomp_data.nr width).
//
// We avoid pulling in unix.SYS_* directly because those are
// arch-local — the sandbox must know the x86_64 number even when
// GOARCH=arm64 and vice versa (not used yet; arm64 table is an
// independent constants block for future cross-arch scenarios).
// Keeping the table explicit also makes ADR-042 reviewable by
// anyone who can grep a number.

type syscallNums struct {
	Execve         uint32
	Execveat       uint32
	Fork           uint32
	Vfork          uint32
	Clone          uint32
	Clone3         uint32
	Unshare        uint32
	Mount          uint32
	Umount2        uint32
	Pivot_root     uint32
	Chroot         uint32
	Ptrace         uint32
	Kexec_load     uint32
	Kexec_file_load uint32
	Init_module    uint32
	Finit_module   uint32
	Delete_module  uint32
	Bpf            uint32
	Reboot         uint32
	Setns          uint32
	Personality    uint32

	// per-profile extras
	Truncate   uint32
	Ftruncate  uint32
	Unlink     uint32
	Unlinkat   uint32
	Mknod      uint32
	Mknodat    uint32
	Chmod      uint32
	Fchmod     uint32
	Fchmodat   uint32
	Rename     uint32
	Renameat   uint32
	Renameat2  uint32
	Symlink    uint32
	Symlinkat  uint32
	Link       uint32
	Linkat     uint32

	Socket     uint32
	Socketpair uint32
	Bind       uint32
	Connect    uint32
	Listen     uint32
	Accept     uint32
	Accept4    uint32
	Sendto     uint32
	Sendmsg    uint32
	Sendmmsg   uint32
	Setsockopt uint32
}

// syscallsAMD64 is the x86_64 Linux syscall number table. Source:
// https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
// Committed inline so audits can diff without tooling.
var syscallsAMD64 = syscallNums{
	Execve:          59,
	Execveat:        322,
	Fork:            57,
	Vfork:           58,
	Clone:           56,
	Clone3:          435,
	Unshare:         272,
	Mount:           165,
	Umount2:         166,
	Pivot_root:      155,
	Chroot:          161,
	Ptrace:          101,
	Kexec_load:      246,
	Kexec_file_load: 320,
	Init_module:     175,
	Finit_module:    313,
	Delete_module:   176,
	Bpf:             321,
	Reboot:          169,
	Setns:           308,
	Personality:     135,

	Truncate:  76,
	Ftruncate: 77,
	Unlink:    87,
	Unlinkat:  263,
	Mknod:     133,
	Mknodat:   259,
	Chmod:     90,
	Fchmod:    91,
	Fchmodat:  268,
	Rename:    82,
	Renameat:  264,
	Renameat2: 316,
	Symlink:   88,
	Symlinkat: 266,
	Link:      86,
	Linkat:    265,

	Socket:     41,
	Socketpair: 53,
	Bind:       49,
	Connect:    42,
	Listen:     50,
	Accept:     43,
	Accept4:    288,
	Sendto:     44,
	Sendmsg:    46,
	Sendmmsg:   307,
	Setsockopt: 54,
}

// syscallsARM64 is the aarch64 Linux syscall number table. Source:
// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h
// aarch64 uses the generic syscall table (no legacy fork/vfork/
// creat/etc); we record fork/vfork as 0 so the denylist compiler
// skips them (see blockedSyscalls filter for zero entries).
var syscallsARM64 = syscallNums{
	Execve:          221,
	Execveat:        281,
	Fork:            0, // not exposed on arm64 generic ABI
	Vfork:           0,
	Clone:           220,
	Clone3:          435,
	Unshare:         97,
	Mount:           40,
	Umount2:         39,
	Pivot_root:      41,
	Chroot:          51,
	Ptrace:          117,
	Kexec_load:      104,
	Kexec_file_load: 294,
	Init_module:     105,
	Finit_module:    273,
	Delete_module:   106,
	Bpf:             280,
	Reboot:          142,
	Setns:           268,
	Personality:     92,

	Truncate:  45,
	Ftruncate: 46,
	Unlink:    0, // arm64 generic uses unlinkat
	Unlinkat:  35,
	Mknod:     0, // arm64 generic uses mknodat
	Mknodat:   33,
	Chmod:     0, // arm64 generic uses fchmodat
	Fchmod:    52,
	Fchmodat:  53,
	Rename:    0, // arm64 generic uses renameat
	Renameat:  38,
	Renameat2: 276,
	Symlink:   0,
	Symlinkat: 36,
	Link:      0,
	Linkat:    37,

	Socket:     198,
	Socketpair: 199,
	Bind:       200,
	Connect:    203,
	Listen:     201,
	Accept:     202,
	Accept4:    242,
	Sendto:     206,
	Sendmsg:    211,
	Sendmmsg:   269,
	Setsockopt: 208,
}

// blockedSyscalls returns the deduped, zero-filtered list of
// syscall numbers to deny for the given profile. Zeros are
// dropped so an arch that doesn't expose a syscall (e.g. fork on
// arm64 generic) doesn't accidentally match nr=0 (which is read()
// on many arches).
func blockedSyscalls(p Profile, n syscallNums) []uint32 {
	// Base blocklist — applies to every offensive profile.
	// Corresponds to ADR-042's "block" list for exploit.
	base := []uint32{
		n.Execve, n.Execveat,
		n.Fork, n.Vfork, n.Clone3,
		n.Unshare,
		n.Mount, n.Umount2,
		n.Pivot_root, n.Chroot,
		n.Ptrace,
		n.Kexec_load, n.Kexec_file_load,
		n.Init_module, n.Finit_module, n.Delete_module,
		n.Bpf,
		n.Reboot,
		n.Setns,
		n.Personality,
	}
	// Note: `clone` (plain) is NOT in base — the Go runtime uses
	// CLONE_THREAD for every goroutine-backing OS thread. Blocking
	// clone entirely would kill the process immediately.

	var extra []uint32
	switch p {
	case ProfileHarvest:
		// Harvest can read + connect outbound but must not mutate
		// on-disk state. File-destructive syscalls get EPERM.
		extra = []uint32{
			n.Truncate, n.Ftruncate,
			n.Unlink, n.Unlinkat,
			n.Mknod, n.Mknodat,
			n.Chmod, n.Fchmod, n.Fchmodat,
			n.Rename, n.Renameat, n.Renameat2,
			n.Symlink, n.Symlinkat,
			n.Link, n.Linkat,
		}
	case ProfileDial:
		// Dial works through /dev/tty* via open+ioctl. It must not
		// open fresh network sockets; AT-command sessions stay
		// local. Anything that spawns a new net-path gets EPERM.
		extra = []uint32{
			n.Socket, n.Socketpair,
			n.Bind, n.Connect, n.Listen,
			n.Accept, n.Accept4,
			n.Sendto, n.Sendmsg, n.Sendmmsg,
			n.Setsockopt,
		}
	case ProfileExploit:
		// Base blocklist already covers the exploit surface ADR-042
		// calls out (no process-spawn, no namespace-escape, no
		// module-load, no ptrace). Network + fs I/O are allowed
		// because the exploit IS network I/O.
	}

	all := make([]uint32, 0, len(base)+len(extra))
	all = append(all, base...)
	all = append(all, extra...)
	return dedupeNonZero(all)
}

// dedupeNonZero returns the input slice with duplicates and zero
// entries removed, preserving order. Zero means "syscall not
// defined for this arch" (see arm64's fork); keeping it in the
// blocklist would accidentally match read() (SYS_read = 0 on many
// arches).
func dedupeNonZero(in []uint32) []uint32 {
	seen := make(map[uint32]struct{}, len(in))
	out := make([]uint32, 0, len(in))
	for _, v := range in {
		if v == 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
