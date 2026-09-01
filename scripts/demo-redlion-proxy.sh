#!/usr/bin/env bash
# demo-redlion-proxy.sh — end-to-end demo of the Red Lion Crimson v3
# write-gated proxy against the bundled redlion-sim, with no real
# Crimson panel.
#
# It builds the offensive binary + redlion-sim, creates a throwaway
# vault in a temp dir (never touches ~/.elsereno), mints the session
# confirm-token, starts the simulator + the proxy, then sends three CR3
# frames through the proxy and prints what came back:
#
#   MemRead    0x1b00 -> forwarded -> sim response (read opcode)
#   Chunk      0x1500 -> forwarded -> sim response (allowlisted)
#   ValueWrite 0x1300 -> REFUSED   -> connection closed, empty
#
# CR3 has no per-request NAK, so a refusal CLOSES the connection
# (fail-closed): the denied frame returns nothing AND never reaches the
# sim (proven by the sim log at the end).
#
# Everything is torn down on exit. Requires: go, nc, xxd.
#
# The CODESYS / GE-SRTP / SLMP / FINS counterparts live alongside.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=15927          # simulator (upstream "HMI") port
PXP=15928           # proxy listen port
TMP="$(mktemp -d)"  # isolated elsereno HOME (vault/audit/config)
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/redlion-sim"
SIMLOG="$TMP/sim.log"
SIMPID=""
PXPID=""

cleanup() {
	[ -n "$PXPID" ] && kill "$PXPID" 2>/dev/null || true
	[ -n "$SIMPID" ] && kill "$SIMPID" 2>/dev/null || true
	pkill -f "$TMP" 2>/dev/null || true
	chmod -R u+w "$TMP" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

el() { HOME="$TMP" "$BIN" "$@"; }

send() { # $1 = label, $2 = frame hex-escaped
	printf '  %-30s' "$1"
	{ printf "$2"; sleep 1; } | nc 127.0.0.1 "$PXP" | xxd -p | tr -d '\n'
	echo
}

echo "==> building offensive binary + redlion-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/redlion

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (allow 0x1500 config/firmware chunk)"
TOK="$(el write redlion proxy-dry-run \
	--target "127.0.0.1:$SIMP" --redlion-type 0x1500 \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting redlion-sim (127.0.0.1:$SIMP)"
"$SIM" -addr "127.0.0.1:$SIMP" >"$SIMLOG" 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
HOME="$TMP" "$BIN" proxy listen --plugin redlion \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	--redlion-type 0x1500 \
	--accept-writes --confirm-target "127.0.0.1:$SIMP" \
	--confirm-token "$TOK" --vault-passphrase-file "$PP" >"$TMP/proxy.log" 2>&1 &
PXPID=$!
sleep 1
kill -0 "$PXPID" 2>/dev/null || {
	echo "proxy failed to start:" >&2
	cat "$TMP/proxy.log" >&2
	exit 1
}

echo "==> sending CR3 frames through the gate (response bytes, hex):"
# CR3 frame = length(BE, body bytes) + reg(BE) + type(BE). Minimal body
# is reg+type (4 bytes) -> length 0x0004; type sits at offset 4.
send "MemRead    0x1b00 (pass):"  '\x00\x04\x00\x00\x1b\x00'
send "Chunk      0x1500 (allow):" '\x00\x04\x00\x00\x15\x00'
send "ValueWrite 0x1300 (deny):"  '\x00\x04\x00\x00\x13\x00'

echo
echo "==> what the sim actually received (proves the deny never arrived):"
grep -c 'received' "$SIMLOG" | xargs printf '  sim saw %s frame(s) (expected 2: MemRead + Chunk)\n'
sed 's/^/  /' "$SIMLOG"

echo
echo "Expected: the first two return the sim's canned CR3 response (0004 0000 0200);"
echo "the ValueWrite returns nothing (proxy closed the connection) and never reached the sim."
