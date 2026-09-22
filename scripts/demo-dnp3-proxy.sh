#!/usr/bin/env bash
# demo-dnp3-proxy.sh — end-to-end demo of the DNP3 write-gated proxy,
# focused on the poster's thesis: Select/Operate move breakers and no
# frame says who you are, so the gate scopes control by CROB
# (point-index + control-code), refuses broadcast, and pins the
# master->outstation link address.
#
# It builds the offensive binary + dnp3-sim, creates a throwaway vault,
# mints the session confirm-token, starts the outstation + the proxy,
# then sends five frames through the proxy and prints the responses:
#
#   Read Class 0            -> forwarded -> outstation IIN response
#   Direct Operate LATCH pt5-> forwarded -> outstation IIN response (allowlisted)
#   Direct Operate TRIP pt5 -> REFUSED   -> IIN2 FUNC_NOT_SUPP (0x04) from the gate
#   Direct Operate broadcast-> REFUSED   -> broadcast control never scopes
#   Cold Restart            -> REFUSED   -> FC not in the app-FC allowlist
#
# Allowlist: --dnp3-app-fc 0x05 (Direct Operate), --dnp3-control
# index=5-8;code=0x03,0x04 (LATCH_ON/OFF only, no TRIP/CLOSE),
# --dnp3-link src=2;dest=1. The passes reach the outstation; the
# refusals do not (proven by the outstation log at the end).
#
# Refused frames carry IIN2 bit 2 set (byte at offset 14 = 0x04). The
# passes carry IIN2 = 0x00 from the outstation.
#
# Everything is torn down on exit. Requires: go.
#
# The Modbus / CODESYS / GE-SRTP / SLMP / FINS counterparts live
# alongside in scripts/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=15931          # outstation port
PXP=15932           # proxy listen port
TMP="$(mktemp -d)"
PP="$TMP/vault.pp"
printf 'demo-passphrase-please-change' >"$PP"
chmod 600 "$PP"

BIN="$TMP/elsereno"
SIM="$TMP/dnp3-sim"
SIMLOG="$TMP/sim.log"
SIMPID=""
PXPID=""

# Session allowlist, passed identically to the dry-run and the proxy.
ALLOW=(--dnp3-app-fc 0x05 --dnp3-control "index=5-8;code=0x03,0x04" --dnp3-link "src=2;dest=1")

cleanup() {
	[ -n "$PXPID" ] && kill "$PXPID" 2>/dev/null || true
	[ -n "$SIMPID" ] && kill "$SIMPID" 2>/dev/null || true
	pkill -f "$TMP" 2>/dev/null || true
	chmod -R u+w "$TMP" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

el() { HOME="$TMP" "$BIN" "$@"; }

send() { # $1 = label, $2 = -send case
	printf '  %-38s' "$1"
	"$SIM" -send "$2" -addr "127.0.0.1:$PXP" 2>/dev/null || true
}

echo "==> building offensive binary + dnp3-sim"
go build -tags offensive -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/dnp3

echo "==> creating throwaway vault in $TMP"
el vault init --vault-passphrase-file "$PP" >/dev/null

echo "==> minting the session confirm-token (LATCH on points 5-8; no TRIP/CLOSE)"
TOK="$(el write dnp3 proxy-dry-run \
	--target "127.0.0.1:$SIMP" "${ALLOW[@]}" \
	--vault-passphrase-file "$PP" | awk -F': ' '/Confirm-token:/{print $2}')"
[ -n "$TOK" ] || { echo "failed to mint token" >&2; exit 1; }

echo "==> starting dnp3-sim outstation (127.0.0.1:$SIMP; reports a Device Restart in its IIN)"
"$SIM" -listen "127.0.0.1:$SIMP" -iin restart >"$SIMLOG" 2>&1 &
SIMPID=$!

echo "==> starting write-gated proxy (127.0.0.1:$PXP -> 127.0.0.1:$SIMP)"
HOME="$TMP" "$BIN" proxy listen --plugin dnp3 \
	--listen "127.0.0.1:$PXP" --target "127.0.0.1:$SIMP" \
	"${ALLOW[@]}" \
	--accept-writes --confirm-target "127.0.0.1:$SIMP" \
	--confirm-token "$TOK" --vault-passphrase-file "$PP" >"$TMP/proxy.log" 2>&1 &
PXPID=$!
sleep 1
kill -0 "$PXPID" 2>/dev/null || { echo "proxy failed to start:" >&2; cat "$TMP/proxy.log" >&2; exit 1; }

echo "==> sending frames through the gate (response bytes, hex):"
send "Read Class 0                (pass):" read
send "Direct Operate LATCH pt5    (pass):" latch5
send "Direct Operate TRIP  pt5    (deny):" trip5
send "Direct Operate broadcast    (deny):" bcast-latch
send "Cold Restart                (deny):" coldrestart

echo
echo "==> IIN monitor (response path): the poster's 'free IDS' that rides in the"
echo "    reply nobody reads. The outstation reports a Device Restart; the proxy"
echo "    surfaces it from the responses that passed:"
grep -i "IIN alert" "$TMP/proxy.log" | sed 's/^/  /' | head -2 || echo "  (no IIN alert logged)"

echo
echo "==> the same alert lands in the tamper-evident audit chain (dnp3_iin_alert):"
grep -o 'dnp3_iin_alert' "$TMP/.elsereno/audit.jsonl" 2>/dev/null | head -1 | sed 's/^/  found audit event_type: /' || echo "  (no audit row)"
HOME="$TMP" "$BIN" audit verify-file --vault-passphrase-file "$PP" >/dev/null 2>&1 && echo "  audit chain verify-file: OK (hash chain intact)" || echo "  audit chain verify-file: (n/a)"

echo
echo "==> what the outstation actually received (proves the denies never arrived):"
sed 's/^/  /' "$SIMLOG"

echo
echo "Expected: Read + LATCH pt5 reach the outstation and reply with IIN1=0x80"
echo "(Device Restart), which the proxy surfaces as a state_change alert. TRIP,"
echo "broadcast and Cold Restart each return an IIN2 FUNC_NOT_SUPP (byte 0x04 at"
echo "offset 14) from the GATE and never appear in the outstation log."
