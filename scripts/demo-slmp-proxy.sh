#!/usr/bin/env bash
# demo-slmp-proxy.sh — end-to-end demo of the SLMP write-gated proxy
# against the bundled slmp-sim, with no real Mitsubishi PLC.
#
# It builds the offensive binary + slmp-sim, creates a throwaway vault
# in a temp dir (never touches ~/.elsereno), mints the session
# confirm-token, starts the simulator + the proxy, then sends three
# SLMP frames through the proxy and prints what came back:
#
#   Device Read Batch  (0x0401) -> forwarded  -> sim success
#   Device Write Batch (0x1401) -> forwarded  -> sim success   (allowlisted)
#   Remote Stop        (0x1002) -> REFUSED    -> native end code 0xC059
#
# Everything is torn down on exit. Requires: go, nc, xxd.
#
# The FINS (UDP) counterpart is scripts/demo-fins-proxy.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=15907          # simulator (upstream "PLC") port
PXP=15908           # proxy listen port
TMP="$(mktemp -d)"  # isolated elsereno HOME (vault/audit/config)
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/slmp-sim"
SIMPID=""
PXPID=""

cleanup() {
	[ -n "$PXPID" ] && kill "$PXPID" 2>/dev/null || true
	[ -n "$SIMPID" ] && kill "$SIMPID" 2>/dev/null || true
	# Safety net: reap any process still referencing this temp dir
	# (e.g. an orphaned child) before removing it.
	pkill -f "$TMP" 2>/dev/null || true
	chmod -R u+w "$TMP" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

# el() runs the elsereno binary with an isolated HOME so the vault,
# audit log, and config live in $TMP and never touch ~/.elsereno.
el() { HOME="$TMP" "$BIN" "$@"; }

send() { # $1 = label, $2 = frame hex-escaped
	printf '  %-32s' "$1"
	{ printf "$2"; sleep 1; } | nc 127.0.0.1 "$PXP" | xxd -p | tr -d '\n'
	echo
}

# Build with the REAL environment (normal $HOME / module cache); only
# the elsereno runtime below gets the isolated HOME.
echo "==> building offensive binary + slmp-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/slmp

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (allow 0x1401 Device Write Batch)"
TOK="$(el write slmp proxy-dry-run \
	--target "127.0.0.1:$SIMP" --slmp-command 0x1401 \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting slmp-sim (127.0.0.1:$SIMP)"
"$SIM" -addr "127.0.0.1:$SIMP" >/dev/null 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
# Launch the binary DIRECTLY (not via the el() function) so $! captures
# the elsereno PID itself; backgrounding a function call would capture
# the subshell PID and leak the real process on cleanup.
HOME="$TMP" "$BIN" proxy listen --plugin slmp \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	--slmp-command 0x1401 \
	--accept-writes --confirm-target "127.0.0.1:$SIMP" \
	--confirm-token "$TOK" --vault-passphrase-file "$PP" >"$TMP/proxy.log" 2>&1 &
PXPID=$!
sleep 1
kill -0 "$PXPID" 2>/dev/null || {
	echo "proxy failed to start:" >&2
	cat "$TMP/proxy.log" >&2
	exit 1
}

echo "==> sending frames through the gate (response bytes, hex):"
# 3E-binary requests: subheader 5000, net/pc/io/stn, len 0006, monitor 0000, command, subcommand 0000.
send "Device Read  0x0401 (pass):"  '\x50\x00\x00\xFF\xFF\x03\x00\x06\x00\x00\x00\x01\x04\x00\x00'
send "Device Write 0x1401 (allow):" '\x50\x00\x00\xFF\xFF\x03\x00\x06\x00\x00\x00\x01\x14\x00\x00'
send "Remote Stop  0x1002 (deny):"  '\x50\x00\x00\xFF\xFF\x03\x00\x06\x00\x00\x00\x02\x10\x00\x00'

echo
echo "Expected: the first two carry end code 0x0000 (success, subheader d000);"
echo "the Remote Stop carries end code 0xC059 (5x c0, refused) and never reached the sim."
