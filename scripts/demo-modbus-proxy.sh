#!/usr/bin/env bash
# demo-modbus-proxy.sh — end-to-end demo of the Modbus/TCP write-gated
# proxy, focused on the FC 8 (Diagnostics) per-sub-function gate.
#
# It builds the offensive binary + modbus-sim, creates a throwaway
# vault in a temp dir (never touches ~/.elsereno), mints the session
# confirm-token, starts the simulator + the proxy, then sends four
# frames through the proxy and prints the response bytes:
#
#   FC 3  Read Holding Registers        -> forwarded -> register bytes
#   FC 8/0x0000 Return Query Data (read)-> forwarded -> loopback echo
#   FC 8/0x0004 Force Listen Only (DoS) -> REFUSED   -> exception 0x88 0x01
#   FC 8/0x000A Clear Counters          -> REFUSED   -> exception 0x88 0x01
#
# Unlike CODESYS/GE-SRTP (which close the connection on refuse), Modbus
# has a native exception frame, so a refused write returns FC|0x80 plus
# IllegalFunction (0x01) and the connection stays open. The mutating FC 8
# sub-functions are the point: Force Listen Only silences a PLC and Clear
# Counters wipes its diagnostic forensics, so both are default-denied and
# never reach the device (proven by the sim log at the end). Read/echo/
# counter sub-functions forward freely; mutating ones need an explicit
# --diag-subfunction on BOTH the dry-run mint and the proxy.
#
# Everything is torn down on exit. Requires: go, nc, xxd.
#
# The CODESYS / GE-SRTP / SLMP / FINS counterparts live alongside.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=15927          # simulator (upstream "PLC") port
PXP=15928           # proxy listen port
TMP="$(mktemp -d)"  # isolated elsereno HOME (vault/audit/config)
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/modbus-sim"
SIMLOG="$TMP/sim.log"
SIMPID=""
PXPID=""

# Session allowlist: one write (FC 6, unit 1, addr 0..100) so the token
# is non-empty, and NO --diag-subfunction, so every mutating FC 8 stays
# denied. To authorise, say, Force Listen Only, add
# `--diag-subfunction 0x04` to BOTH the dry-run and the proxy below.
WRITE="unit=1;fc=6;start=0;end=100"

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
	printf '  %-42s' "$1"
	{ printf "$2"; sleep 1; } | nc 127.0.0.1 "$PXP" | xxd -p | tr -d '\n'
	echo
}

echo "==> building offensive binary + modbus-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/modbus

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (allow write $WRITE; no mutating diag)"
TOK="$(el write modbus proxy-dry-run \
	--target "127.0.0.1:$SIMP" --write "$WRITE" \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting modbus-sim (127.0.0.1:$SIMP)"
"$SIM" -listen "127.0.0.1:$SIMP" >"$SIMLOG" 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
HOME="$TMP" "$BIN" proxy listen --plugin modbus \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	--write "$WRITE" \
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
# MBAP = TxID(2) Proto(0000) Len(2) Unit(1) ; then the PDU.
send "FC3 Read Holding Regs 0..3 (pass):"       '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x04'
send "FC8/0x00 Return Query Data (read pass):"  '\x00\x02\x00\x00\x00\x06\x01\x08\x00\x00\xab\xcd'
send "FC8/0x04 Force Listen Only (DoS deny):"   '\x00\x03\x00\x00\x00\x06\x01\x08\x00\x04\x00\x00'
send "FC8/0x0A Clear Counters   (deny):"        '\x00\x04\x00\x00\x00\x06\x01\x08\x00\x0a\xff\x00'

echo
echo "==> what the sim actually received (proves the denies never arrived):"
sed 's/^/  /' "$SIMLOG"

echo
echo "Expected: FC3 returns 8 register bytes (0803 + 4x uint16);"
echo "FC8/0x00 echoes back 0800 00abcd (loopback); FC8/0x04 and FC8/0x0A"
echo "each return 8801 (IllegalFunction) from the GATE and never reach the sim."
