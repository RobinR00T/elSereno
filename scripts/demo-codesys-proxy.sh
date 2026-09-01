#!/usr/bin/env bash
# demo-codesys-proxy.sh — end-to-end demo of the CODESYS v3 write-gated
# proxy against the bundled codesys-sim, with no real CODESYS runtime.
#
# It builds the offensive binary + codesys-sim, creates a throwaway
# vault in a temp dir (never touches ~/.elsereno), mints the session
# confirm-token, starts the simulator + the proxy, then sends three
# CODESYS L7 messages through the proxy and prints what came back:
#
#   CmpApp/ReadStatus (0x02:0x14) -> forwarded -> sim response (read)
#   CmpApp/Start      (0x02:0x10) -> forwarded -> sim response (allowlisted)
#   CmpApp/Download   (0x02:0x05) -> REFUSED   -> connection closed, empty
#
# CODESYS has no per-request NAK, so a refusal CLOSES the connection
# (fail-closed): the denied message returns nothing AND never reaches
# the sim (proven by the sim log at the end).
#
# Everything is torn down on exit. Requires: go, nc, xxd.
#
# The GE-SRTP / SLMP / FINS counterparts live alongside in scripts/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=15917          # simulator (upstream "PLC") port
PXP=15918           # proxy listen port
TMP="$(mktemp -d)"  # isolated elsereno HOME (vault/audit/config)
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/codesys-sim"
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
	printf '  %-34s' "$1"
	{ printf "$2"; sleep 1; } | nc 127.0.0.1 "$PXP" | xxd -p | tr -d '\n'
	echo
}

echo "==> building offensive binary + codesys-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/codesys

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (allow 0x02:0x10 CmpApp/Start)"
TOK="$(el write codesys proxy-dry-run \
	--target "127.0.0.1:$SIMP" --codesys-command 0x02:0x10 \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting codesys-sim (127.0.0.1:$SIMP)"
"$SIM" -addr "127.0.0.1:$SIMP" >"$SIMLOG" 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
HOME="$TMP" "$BIN" proxy listen --plugin codesys \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	--codesys-command 0x02:0x10 \
	--accept-writes --confirm-target "127.0.0.1:$SIMP" \
	--confirm-token "$TOK" --vault-passphrase-file "$PP" >"$TMP/proxy.log" 2>&1 &
PXPID=$!
sleep 1
kill -0 "$PXPID" 2>/dev/null || {
	echo "proxy failed to start:" >&2
	cat "$TMP/proxy.log" >&2
	exit 1
}

echo "==> sending L7 messages through the gate (response bytes, hex):"
# frame = L2 prefix (magic 000117e8 + junk) + L7 header (magic 55cd,
# header_size 0, service_id, 0, cmd_id, 0).
send "CmpApp/ReadStatus 0x02:0x14 (pass):"  '\x00\x01\x17\xe8\x40\x00\x00\x00\x55\xcd\x00\x00\x02\x00\x14\x00'
send "CmpApp/Start      0x02:0x10 (allow):" '\x00\x01\x17\xe8\x40\x00\x00\x00\x55\xcd\x00\x00\x02\x00\x10\x00'
send "CmpApp/Download   0x02:0x05 (deny):"  '\x00\x01\x17\xe8\x40\x00\x00\x00\x55\xcd\x00\x00\x02\x00\x05\x00'

echo
echo "==> what the sim actually received (proves the deny never arrived):"
grep -c 'received' "$SIMLOG" | xargs printf '  sim saw %s message(s) (expected 2: ReadStatus + Start)\n'
sed 's/^/  /' "$SIMLOG"

echo
echo "Expected: the first two return the sim's canned L7 response (55cd..8200..);"
echo "the Download returns nothing (proxy closed the connection) and never reached the sim."
