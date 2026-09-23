#!/usr/bin/env bash
# demo-goose-monitor.sh: end-to-end demo of the IEC 61850 GOOSE passive
# spoofing monitor. It shows the canonical substation attack and how the
# monitor catches it, entirely offline (no capture, no network).
#
# The GOOSE spoofing attack: a publisher signals a protection event
# (trip a breaker) by incrementing stNum. An attacker injects a frame
# with a HIGHER stNum than the real publisher, so subscribers accept the
# attacker's dataset and act on a forged trip. The monitor flags that
# stNum jump (plus the simulation/test bit and other tells).
#
# This script builds the binary, writes a small frame stream (one hex
# Ethernet frame per line), and runs `goose monitor` over it.
set -euo pipefail
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

bin="$(mktemp -d)/elsereno"
frames="$(mktemp)"
trap 'rm -f "$frames"; rm -rf "$(dirname "$bin")"' EXIT

echo ":: building elsereno"
go build -o "$bin" ./cmd/elsereno

# Each line is a full Ethernet frame in hex:
#   dst(01:0c:cd:01:00:01) src(00:11:22:33:44:55) ethertype(88b8=GOOSE)
#   GOOSE hdr: APPID(0001) Length Reserved1(0000) Reserved2(0000)
#   APDU 0x61: goID "t", ttl 10ms, stNum, sqNum, confRev [, test bit]
cat > "$frames" <<'FRAMES'
# baseline: real publisher, stNum 1
010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850101 860100 880101
# heartbeat: same state, sqNum advances (normal, no event)
010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850101 860101 880101
# ATTACK: injected frame with a high stNum to override the publisher
010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850109 860100 880101
# ATTACK: simulation/test bit set (subscribers may honour simulated data)
010ccd010001001122334455 88b8 0001 001c 00000000 6112 830174 81010a 85010a 860100 880101 8701ff
FRAMES

echo
echo ":: decode the baseline frame"
"$bin" goose decode --hex "010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850101 860100 880101"

echo
echo ":: run the anomaly monitor over the stream"
"$bin" goose monitor --file "$frames"

echo
echo ":: expected: a stnum_jump on the injected frame and a test_bit_set on the last."
