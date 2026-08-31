#!/usr/bin/env bash
# demo-fins-proxy.sh — end-to-end demo of the FINS write-gated proxy
# (UDP) against the bundled fins-sim, with no real Omron PLC.
#
# It builds the offensive binary + fins-sim, creates a throwaway vault
# in a temp dir (never touches ~/.elsereno), mints the session
# confirm-token, starts the simulator + the proxy, then sends three
# FINS/UDP datagrams through the proxy and prints what came back:
#
#   Controller Data Read (0x05/0x01) -> forwarded -> sim model reply
#   Memory Area Write    (0x01/0x02) -> forwarded -> sim success  (allowlisted)
#   Stop / mode-change   (0x04/0x02) -> REFUSED   -> native end code 0x2101
#
# Everything is torn down on exit. Requires: go, nc, xxd.
#
# The SLMP (TCP) counterpart is scripts/demo-slmp-proxy.sh. Both use
# the Options.Network transport in internal/proxy (finsudp -> udp).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=19600          # simulator (upstream "PLC") UDP port
PXP=19610           # proxy listen UDP port
TMP="$(mktemp -d)"  # isolated elsereno HOME (vault/audit/config)
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/fins-sim"
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
	printf "$2" | nc -u -w1 127.0.0.1 "$PXP" | xxd -p | tr -d '\n'
	echo
}

echo "==> building offensive binary + fins-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/finsudp

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (allow 0x01:0x02 Memory Area Write)"
TOK="$(el write finsudp proxy-dry-run \
	--target "127.0.0.1:$SIMP" --fins-command 0x01:0x02 \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting fins-sim (127.0.0.1:$SIMP, udp)"
"$SIM" -addr "127.0.0.1:$SIMP" >/dev/null 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (udp 127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
HOME="$TMP" "$BIN" proxy listen --plugin finsudp \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	--fins-command 0x01:0x02 \
	--accept-writes --confirm-target "127.0.0.1:$SIMP" \
	--confirm-token "$TOK" --vault-passphrase-file "$PP" >"$TMP/proxy.log" 2>&1 &
PXPID=$!
sleep 1
kill -0 "$PXPID" 2>/dev/null || {
	echo "proxy failed to start:" >&2
	cat "$TMP/proxy.log" >&2
	exit 1
}

echo "==> sending datagrams through the gate (response bytes, hex):"
# FINS/UDP: 10-byte header (ICF 0x80 request, SID 0x42/0x2A) + MRC + SRC + data.
send "Controller Read 0x05:01 (pass):"  '\x80\x00\x02\x00\x00\x00\x00\x01\x00\x42\x05\x01\x00'
send "Memory Write    0x01:02 (allow):" '\x80\x00\x02\x00\x00\x00\x00\x01\x00\x2A\x01\x02\xB0\x00\x64\x00\x00\x01\x12\x34'
send "Stop            0x04:02 (deny):"  '\x80\x00\x02\x00\x00\x00\x00\x01\x00\x2A\x04\x02'

echo
echo "Expected: the first two carry end code 0x0000 (success, ICF 0xC0 response);"
echo "the Stop carries end code 0x2101 (…2101, refused) and never reached the sim."
