# IEC 61850 GOOSE / SV (substation bus, L2)

**EtherType**: 0x88B8 (GOOSE, IEC 61850-8-1), 0x88BA (Sampled Values,
IEC 61850-9-2). 802.1Q VLAN-tagged frames are handled.
**Status**: offline dissector + passive anomaly monitor.
**Build**: default (this is a defensive monitor, not an offensive
write-gate).

## Scope

Like the `profinet` verb, this is an **offline** workflow: feed it
frames captured with `tcpdump -xx` / `tshark`. It never opens a socket.
Live L2 capture (raw sockets + `CAP_NET_RAW`) stays vNext.

```
elsereno goose decode  --hex 0x...        # dissect one frame
elsereno goose monitor --file frames.txt  # run the anomaly monitor
```

`monitor` reads one hex-encoded Ethernet frame per line (blank lines and
`#` comments ignored); non-GOOSE/SV frames are skipped, so a mixed
capture is fine. Produce the input with e.g.:

```
tshark -r substation.pcap -Y 'goose || sv' -T fields -e frame.raw > frames.txt
```

## Why GOOSE spoofing matters

A GOOSE publisher signals a protection event (trip a breaker, block a
recloser) by incrementing **stNum** and resetting **sqNum**. Subscribers
act on the highest stNum they have seen. The canonical attack injects a
frame with a **higher stNum** than the real publisher, so subscribers
latch the attacker's dataset and act on a forged trip. GOOSE has no
authentication on the wire, so this is passively observable but not
preventable at L2: detection is the control.

## What the monitor flags

Keyed per publisher (goID, falling back to gocbRef; svID for SV):

| Event | Severity | Meaning |
|---|---|---|
| `stnum_jump` | high | stNum increased by more than the threshold (default 1). The high-stNum override tell. |
| `stnum_regression` | high | stNum went backwards. A live publisher never rewinds: replay / rollback. |
| `test_bit_set` | high | simulation/test bit set. Subscribers honouring simulation accept the frame as live. |
| `ndscom_set` | medium | ndsCom (needs commissioning) set in steady state. |
| `confrev_change` | medium | confRev changed mid-stream (reconfiguration, or a spoof that did not clone confRev). |
| `sqnum_anomaly` | low | sqNum did not advance within an stNum epoch (stall / rewind). |
| `state_change` | info | normal +1 stNum step (a protection event fired); recorded for the audit trail. |
| `sv_smpcnt_regression` | medium | SV smpCnt went backwards for an svID (not a plausible sample-count wrap). |
| `sv_confrev_change` | medium | SV confRev changed mid-stream. |

`--stnum-jump-threshold N` widens the normal-step tolerance; `--json`
emits each event as an NDJSON line for a SIEM.

## Wire

The dissector strips the Ethernet (and optional 802.1Q) header, reads
the reserved GOOSE/SV header (APPID + Length + two Reserved words), and
BER-decodes the IECGoosePdu `[APPLICATION 1]` / savPdu `[APPLICATION 0]`
template (IEC 61850-8-1 §A.3), the same field layout the Wireshark
`packet-goose` dissector parses. See `internal/protocols/goose/wire.go`.

## Demo

```
bash scripts/demo-goose-monitor.sh
```

Builds the binary, writes a four-frame stream (baseline, heartbeat, a
high-stNum injection, a test-bit injection), and shows the monitor
catching the two attacks while leaving the normal heartbeat silent.
