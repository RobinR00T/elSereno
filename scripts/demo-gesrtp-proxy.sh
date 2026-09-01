#!/usr/bin/env bash
# demo-gesrtp-proxy.sh — end-to-end demo of the GE-SRTP write-gated
# proxy against the bundled gesrtp-sim, with no real PACSystems PLC.
#
# It builds the offensive binary + gesrtp-sim, creates a throwaway vault
# in a temp dir (never touches ~/.elsereno), mints the session
# confirm-token, starts the simulator + the proxy, then sends three
# 56-byte SRTP mailboxes through the proxy and prints what came back:
#
#   READ_SYS_MEM  (0x04) -> forwarded -> sim response (read)
#   WRITE_SYS_MEM (0x07) -> forwarded -> sim response (allowlisted)
#   SET_PLC_RUN   (0x23) -> REFUSED   -> connection closed, empty
#
# SRTP has no per-request NAK, so a refusal CLOSES the connection
# (fail-closed): the denied mailbox returns nothing AND never reaches
# the sim (proven by the sim log at the end).
#
# Everything is torn down on exit. Requires: go, nc, xxd.
#
# The CoDeSys / Red Lion / SLMP / FINS counterparts live alongside.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=15937          # simulator (upstream "PLC") port
PXP=15938           # proxy listen port
TMP="$(mktemp -d)"  # isolated elsereno HOME (vault/audit/config)
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/gesrtp-sim"
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

# mailbox emits a 56-byte SHORT SRTP request mailbox for service $1 (hex
# byte). Layout: [0]=0x02 REQ, [31]=0xC0 short form, [42]=service code.
mailbox() {
	printf '\x02'
	printf '\x00%.0s' $(seq 1 30)
	printf '\xC0'
	printf '\x00%.0s' $(seq 1 10)
	printf "\\x$1"
	printf '\x00%.0s' $(seq 1 13)
}

send() { # $1 = label, $2 = service hex byte
	printf '  %-28s' "$1"
	{ mailbox "$2"; sleep 1; } | nc 127.0.0.1 "$PXP" | xxd -p | tr -d '\n'
	echo
}

echo "==> building offensive binary + gesrtp-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/gesrtp

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (allow 0x07 WRITE_SYS_MEM)"
TOK="$(el write gesrtp proxy-dry-run \
	--target "127.0.0.1:$SIMP" --gesrtp-service 0x07 \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting gesrtp-sim (127.0.0.1:$SIMP)"
"$SIM" -addr "127.0.0.1:$SIMP" >"$SIMLOG" 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
HOME="$TMP" "$BIN" proxy listen --plugin gesrtp \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	--gesrtp-service 0x07 \
	--accept-writes --confirm-target "127.0.0.1:$SIMP" \
	--confirm-token "$TOK" --vault-passphrase-file "$PP" >"$TMP/proxy.log" 2>&1 &
PXPID=$!
sleep 1
kill -0 "$PXPID" 2>/dev/null || {
	echo "proxy failed to start:" >&2
	cat "$TMP/proxy.log" >&2
	exit 1
}

echo "==> sending SRTP mailboxes through the gate (response bytes, hex):"
send "READ_SYS_MEM  0x04 (pass):"  04
send "WRITE_SYS_MEM 0x07 (allow):" 07
send "SET_PLC_RUN   0x23 (deny):"  23

echo
echo "==> what the sim actually received (proves the deny never arrived):"
grep -c 'received' "$SIMLOG" | xargs printf '  sim saw %s mailbox(es) (expected 2: READ + WRITE)\n'
sed 's/^/  /' "$SIMLOG"

echo
echo "Expected: the first two return the sim's canned response mailbox (pkt type 03..);"
echo "the SET_PLC_RUN returns nothing (proxy closed the connection) and never reached the sim."
