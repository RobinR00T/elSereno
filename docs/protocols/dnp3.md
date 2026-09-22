# DNP3 (IEEE 1815, port 20000)

DNP3 (Distributed Network Protocol 3) is the predominant protocol in
North American electric utility SCADA (substations, distribution
automation) and increasingly in water / wastewater. It is cleartext
and unauthenticated in its base form; Secure Authentication v5 (SAv5)
is optional and adds no confidentiality. Select-Before-Operate is an
interlock against a mis-click, not an authorization step, and Direct
Operate skips even that.

## Probe

- Build a link-layer Request Link Status frame (Control byte 0xC9:
  DIR=1, PRM=1, FC=9). 10 bytes fixed size.
- A response that starts with `0x05 0x64` signals a DNP3 outstation.

## Proxy policy (default build)

Every frame's link-layer control byte is classified:

- **CategoryRead**: PRM=0 responses, PRM=1 Test Link (FC 1), PRM=1
  Request Link Status (FC 9). Forward untouched.
- **CategoryWrite**: PRM=1 Reset Link (FC 0), Confirmed User Data
  (FC 3), Unconfirmed User Data (FC 4). The user-data frames carry the
  application layer, so the default build conservatively blocks them.
- **CategoryUnknown**: any primary FC outside the table. Blocked.

Refusal is a secondary FC 15 "Not Supported" frame with the source and
destination swapped and a correct header CRC.

## Writes (`-tags offensive`)

The offensive build replaces the deny-all proxy with a four-layer
write-gate (`offensive/write/dnp3`). Read (FC 1) always passes;
everything else is default-deny.

1. **Link-layer primary FC** (`--dnp3-primary`, optional). By default
   user-data frames pass to the application-layer gate.
2. **Destination link address.** A control or write to a broadcast
   address (`0xFFFD-0xFFFF`) reaches every outstation on the loop at
   once and cannot be scoped, so it is always refused. `--dnp3-link
   src=N;dest=M` pins the accepted master->outstation pairs.
3. **Application-layer FC** (`--dnp3-app-fc`). Write (0x02), Select
   (0x03), Operate (0x04), Direct Operate (0x05/0x06), the restarts
   (0x0D/0x0E), Stop Application (0x12), Disable Unsolicited (0x15) and
   the rest must each be listed to pass.
4. **Control Relay Output Block** (`--dnp3-control`). When set, every
   g12v1 CROB in an Operate / Direct Operate must match a
   `(point-index range, control-code)` entry. This is the lever the
   attack literature turns on: an operator can allow a LATCH on points
   5-8 and still refuse a TRIP (`0x81`) or CLOSE (`0x41`) on any
   breaker.
5. **Analog Output Block** (`--dnp3-analog`). The analog analogue of
   the CROB scope: every g41 setpoint (variations 1-4: int16 / int32 /
   float32 / float64) in an Operate / Direct Operate must match a
   `(point-index range, value window)` entry. `index=10-12;min=0;max=50`
   drives points 10-12 only between 0 and 50 and refuses a setpoint that
   would slam the actuator past the clamp; omit `min`/`max` to allow any
   value on the range. When either the CROB or the analog scope is set,
   a control carrying any other object type is refused (fail-closed).

Refusal is a well-formed DNP3 response carrying `IIN2` bit 2
"FUNC_NOT_SUPP" (byte2 `0x04`) with correct header and block CRCs, so
the master parses it rather than seeing a wire fault. The gate reads
the full block-CRC-framed body and verifies every block CRC: a corrupt
frame fails closed.

```sh
# Mint the token: allow a LATCH on points 5-8 only, pin the master,
# and refuse trips/closes and broadcast controls.
elsereno-offensive write dnp3 proxy-dry-run \
  --target 10.0.0.5:20000 \
  --dnp3-app-fc 0x05 \
  --dnp3-control "index=5-8;code=0x03,0x04" \
  --dnp3-link "src=2;dest=1" \
  --vault-passphrase-file ~/.elsereno/dev.pp

# Run the proxy with the SAME allowlist flags + the minted token.
elsereno-offensive proxy listen --plugin dnp3 \
  --listen 127.0.0.1:20000 --target 10.0.0.5:20000 \
  --dnp3-app-fc 0x05 --dnp3-control "index=5-8;code=0x03,0x04" \
  --dnp3-link "src=2;dest=1" \
  --accept-writes --confirm-target 10.0.0.5:20000 \
  --confirm-token "<TOKEN>" --vault-passphrase-file ~/.elsereno/dev.pp
```

The four allowlist dimensions are bound into the confirm-token (an
empty dimension folds out, so a token stays backwards-compatible). A
minimal end-to-end demonstration with a simulator lives at
`scripts/demo-dnp3-proxy.sh`.

## Response-path IIN monitor

The gate also reads the reply, not just the request. Every DNP3
response (FC 129 / 130) carries two Internal Indications octets that
almost nobody reads, and they are a free intrusion signal:

- **Device Restart** (IIN1 0x80), **Device Trouble** (IIN1 0x40) and
  **Configuration Corrupt** (IIN2 0x20) confirm that something changed
  the outstation's state. The monitor raises a `state_change` alert on
  each, even for a change whose request you missed.
- a run of **Function-not-supported** (IIN2 0x01), **Object-unknown**
  (IIN2 0x02) and **Parameter-error** (IIN2 0x04) responses is the
  signature of somebody enumerating or fuzzing the outstation. The
  monitor raises one `error_burst` alert when the count crosses a
  threshold (default 3, `IINErrorBurstThreshold`).

Monitoring is observation only: every response is forwarded to the
master verbatim before it is inspected, and a framing desync falls back
to a raw copy, so the master's stream is never delayed or corrupted. A
run of identical state-change responses (a stuck bit) collapses to one
alert. Each alert is logged and recorded in the tamper-evident audit
chain as a `dnp3_iin_alert` row (so it survives the session and reaches
the dashboard / SSE feed); an `OnIIN` callback can override the sink.
The demo runs the outstation with `-iin restart` to show the monitor
surfacing a Device Restart from the passing responses and the matching
audit row, then verifies the hash chain is intact.

To ship these detections to a SOC, `elsereno audit export --event-type
dnp3_iin_alert --format cef` emits one ArcSight CEF line per alert (or
`--format syslog` for RFC 5424); pipe it to `logger` or a collector.
The dashboard audit view already lists them (filter `event_type=
dnp3_iin_alert`).

## Attack playbook (mapping to elSereno)

The techniques follow the public DNP3 attack literature (Pascal
Ackerman's "DNP3 Attack & Defend" poster, the ICS-CERT Project Robus
disclosures, and the ATT&CK for ICS matrix). elSereno is primarily a
parsing write-gate: it forwards only what the operator allowlisted,
refuses the rest at parse time, and (with `--record`) captures every
frame that crossed the gate. It also reads the reply path for the IIN
signals below, but it is not a full IDS.

| Technique (ATT&CK for ICS) | DNP3 mechanism | elSereno response |
|-----------------------------|----------------|-------------------|
| Remote System Discovery (T0846) | scan tcp/20000; sweep link addresses 0-65519 behind a serial gateway | `probe` / `scan` identify a live outstation from the `05 64` response |
| Point-map fingerprinting | FC 1 Read of Group 60 Var 1 (Class 0 integrity poll): the full static point map, no session, byte-identical to the master's own poll | Forwarded (read-only) and, with `--record`, timestamped for audit |
| Manipulation of Control (T0831) | FC 4 Operate / FC 5-6 Direct Operate with a CROB: `0x81` trips a breaker, `0x41` closes it | Refused unless the CROB's `(index, control-code)` is allowlisted; `--dnp3-control` lets trips/closes be denied while a latch passes |
| SBO enumeration | FC 3 Select with no Operate: proves a control point is armable, moves nothing, invisible to anything watching only for Operate | Select (0x03) is default-deny; it passes only when explicitly allowlisted |
| Modify Parameter (T0836) | FC 2 Write to the clock; or an Operate / Direct Operate with a g41 Analog Output Block that drives a setpoint to a dangerous value | Write (0x02) is default-deny; a g41 setpoint is refused unless its `(index, value)` matches an `--dnp3-analog` window, so an out-of-range setpoint is clamped out |
| Broadcast control | any control aimed at link address `0xFFFD-0xFFFF` lands on every outstation at once | Always refused for mutating frames, even if the FC and CROB are otherwise allowlisted |
| Spoofed master | a control FC from a non-master IP or link address | `--dnp3-link` pins the master->outstation pair; an unpinned mutating frame is refused |
| Denial of View (T0815) | FC 21 Disable Unsolicited: the outstation stops reporting events and the master keeps a stale picture | Default-deny (not in the app-FC allowlist unless the operator lists 0x15) |
| Device Restart / Shutdown (T0816) | FC 13 Cold Restart, FC 14 Warm Restart, FC 18 Stop Application | Default-deny; and if a restart happens by any path, the response-path monitor raises a `state_change` alert from the reply's IIN |
| Anti-forensics | FC 9/10 Freeze-and-Clear wipes accumulators; the IIN "Device Restart / Config Corrupt" bits are the evidence | Freeze/Clear default-deny; the request is recorded, and the response-path monitor alerts on the Config-Corrupt / Restart IIN bits |
| Enumeration / fuzzing | probing FCs, objects and qualifiers to map the outstation | A run of Function-not-supported / Object-unknown / Parameter-error responses trips one `error_burst` alert from the IIN |
| Program Upload (T0845) | FC 25-30 file operations move config / firmware off or onto the device | Default-deny |
| Malformed-frame abuse | a truncated frame, a bad block CRC, or a CROB with an unsupported qualifier | The gate verifies every block CRC and fails closed; a malformed control is refused, not forwarded |

Note the asymmetry the poster stresses: reads forward (a passive tap
must not break the process it observes), controls and writes are
default-deny, and the single byte that carries the intent (the CROB
control code) is inspected, not waved through with the function code.

## Scope

- DNP3 outstations at power-utility RTUs, DER inverters, reclosers, and
  substation IEDs; a control here throws a physical breaker.
- The link-layer probe is invisible to most deployed DNP3 RTUs and does
  not disrupt Class 0 polling.

## Public references

- IEEE Std 1815-2012; the DNP Users Group object library.
- NIST SP 800-82r3; NERC CIP-005 / CIP-007.
- Wireshark DNP3 dissector (`packet-dnp3.c`); CISA/INL ICSNPP-DNP3.
