#!/usr/bin/env bash
# demo-opcua-https-fingerprint.sh — end-to-end demo of the opcuahttps
# plugin's deep GetEndpoints fingerprint, with no real OPC UA server.
#
# The opcuahttps plugin (TCP/4843, OPC UA HTTPS binding, Part 6 §7.4)
# POSTs a real GetEndpointsRequest and parses the EndpointDescription
# list. This demo starts opcuahttps-sim (a TLS server serving a
# GetEndpointsResponse on 4843, one endpoint SecurityMode=None) and runs
# `elsereno fingerprint probe --plugin opcuahttps` against it. The deep
# path decodes the endpoints; the None endpoint (anonymous, unencrypted
# UA access) pushes exposure/auth_state to 90 and capability to 80.
#
# Everything is torn down on exit. Requires: go (jq optional).
#
# The write-gate demos (FINS/SLMP/GE-SRTP/CoDeSys/Red Lion/OPC UA proxy)
# live alongside in scripts/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SIMP=4843            # opcuahttps DefaultPort — scan matches the opcuahttps plugin here
TMP="$(mktemp -d)"   # isolated elsereno HOME
BIN="$TMP/elsereno"
SIM="$TMP/opcuahttps-sim"
SIMPID=""

cleanup() {
	[ -n "$SIMPID" ] && kill "$SIMPID" 2>/dev/null || true
	pkill -f "$TMP" 2>/dev/null || true
	chmod -R u+w "$TMP" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

echo "==> building binary + opcuahttps-sim"
go build -o "$BIN" ./cmd/elsereno
go build -o "$SIM" ./simulators/opcuahttps

echo "==> starting opcuahttps-sim (TLS GetEndpoints on 127.0.0.1:$SIMP)"
"$SIM" -addr "127.0.0.1:$SIMP" >"$TMP/sim.log" 2>&1 &
SIMPID=$!
sleep 1
kill -0 "$SIMPID" 2>/dev/null || { echo "sim failed to start:" >&2; cat "$TMP/sim.log" >&2; exit 1; }

echo "==> elsereno fingerprint probe --plugin opcuahttps (live GetEndpoints POST):"
HOME="$TMP" "$BIN" fingerprint probe \
	--plugin opcuahttps --target "127.0.0.1:$SIMP" --json 2>&1 \
	| tee "$TMP/finding.json" \
	| sed 's/^/  /'

echo
echo "==> the security-posture factors:"
if command -v jq >/dev/null; then
	jq -c '{protocol, severity, score, capability: .factors.capability, exposure: .factors.exposure, auth_state: .factors.auth_state}' \
		"$TMP/finding.json" | sed 's/^/  /'
fi

echo
echo "Expected: capability=80 (the plugin enumerated the endpoint list), and"
echo "exposure=90 / auth_state=90 from the advertised SecurityMode=None endpoint"
echo "(anonymous, unencrypted UA access)."
