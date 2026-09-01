#!/usr/bin/env bash
# demo-opcua-proxy.sh — end-to-end demo of the OPC UA (opc.tcp) write-
# gated proxy against the bundled opcua-sim, with no real OPC UA server.
#
# It builds the offensive binary + opcua-sim, creates a throwaway vault
# in a temp dir (never touches ~/.elsereno), mints the session
# confirm-token, starts the simulator + the proxy, then sends three
# UA-TCP MSG frames (by service TypeId) through the proxy and prints
# what came back:
#
#   ReadRequest  (631) -> forwarded -> sim response (read, always passes)
#   WriteRequest (673) -> forwarded -> sim response (allowlisted)
#   CallRequest  (704) -> REFUSED   -> native UA ServiceFault (TypeId 397)
#
# Unlike the close-on-refusal gates (CoDeSys/Red Lion/GE-SRTP), OPC UA
# refuses a service per-request with a UA-native ServiceFault and keeps
# the connection open, so the denied CallRequest returns a parseable
# fault frame AND never reaches the sim (proven by the sim log).
#
# Everything is torn down on exit. Requires: go, nc, xxd.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=15947          # simulator (upstream OPC UA server) port
PXP=15948           # proxy listen port
TMP="$(mktemp -d)"  # isolated elsereno HOME (vault/audit/config)
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/opcua-sim"
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

# msg emits a minimal 28-byte UA-TCP MSG frame for service TypeId with
# little-endian bytes $1 $2. Layout: "MSG"+'F' (0x46), length 28 (LE),
# 16-byte zero secure-channel prefix, FourByteNodeId (01 00 lo hi).
msg() { # $1 = TypeId low byte (hex), $2 = high byte (hex)
	printf '\x4d\x53\x47\x46\x1c\x00\x00\x00'
	printf '\x00%.0s' $(seq 1 16)
	printf "\\x01\\x00\\x$1\\x$2"
}

send() { # $1 = label, $2 = TypeId low hex, $3 = TypeId high hex
	printf '  %-30s' "$1"
	{ msg "$2" "$3"; sleep 1; } | nc 127.0.0.1 "$PXP" | xxd -p | tr -d '\n'
	echo
}

echo "==> building offensive binary + opcua-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/opcua

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (allow 673 WriteRequest)"
TOK="$(el write opcua dry-run \
	--target "127.0.0.1:$SIMP" --service 673 \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting opcua-sim (127.0.0.1:$SIMP)"
"$SIM" -addr "127.0.0.1:$SIMP" >"$SIMLOG" 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
HOME="$TMP" "$BIN" proxy listen --plugin opcua \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	--service 673 \
	--accept-writes --confirm-target "127.0.0.1:$SIMP" \
	--confirm-token "$TOK" --vault-passphrase-file "$PP" >"$TMP/proxy.log" 2>&1 &
PXPID=$!
sleep 1
kill -0 "$PXPID" 2>/dev/null || {
	echo "proxy failed to start:" >&2
	cat "$TMP/proxy.log" >&2
	exit 1
}

echo "==> sending MSG frames through the gate (response bytes, hex):"
send "ReadRequest  631 (pass):"  77 02
send "WriteRequest 673 (allow):" a1 02
send "CallRequest  704 (deny):"  c0 02

echo
echo "==> what the sim actually received (proves the deny never arrived):"
grep -c 'received' "$SIMLOG" | xargs printf '  sim saw %s frame(s) (expected 2: Read + Write)\n'
sed 's/^/  /' "$SIMLOG"

echo
echo "Expected: the first two return the sim's canned MSG response (4d534746...);"
echo "the CallRequest returns a UA ServiceFault frame (service TypeId 397 = 8d 01)"
echo "from the proxy and never reaches the sim."
