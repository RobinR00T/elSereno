# DNP3 (IEEE 1815, port 20000)

DNP3 (Distributed Network Protocol 3) is the predominant protocol in
North American electric utility SCADA (substations, distribution
automation) and increasingly in water / wastewater. It is cleartext
and unauthenticated in its base form; Secure Authentication v5 (SAv5)
is optional and adds no confidentiality. Select-Before-Operate is an
interlock against a mis-click, not an authorization step, and Direct
Operate skips even that.

## Probe

- Send link-layer Request Link Status frames (control 0xC9: DIR=1,
  PRM=1, FC=9; 10 octets each, header CRC included) to every
  destination address 0..100 from master address 0, in one write. An
  outstation answers only its own link address, and the scanner does
  not know it; this is the request nmap's `dnp3-info.nse` (DigitalBond
  Redpoint) sends: its 100 well-formed frames byte for byte (its frame
  for address 0x3D carries a typo and is malformed; ours is well
  formed). No application-layer request is
  carried.
- A reply counts as DNP3 when it is a link frame (`0x05 0x64`, length
  of at least 5) whose header CRC is valid. A reflected copy of our own
  frames is rejected first (PITF-071).
- Limit: an outstation above address 100, or one that only answers a
  configured master address, stays silent (same reach as nmap).
- Footprint: the probe is 101 Request Link Status frames from one
  source to 101 destination link addresses. The "DNP3 Attack & Defend"
  poster lists "one source touching many DNP3 destination link
  addresses" among the suspicious patterns and maps the link-address
  sweep to ATT&CK for ICS T0840 Network Connection Enumeration, so a
  DNP3-aware IDS flags it, as it flags nmap's `dnp3-info.nse`. The
  outstation sees only link-layer status requests.
- Until 2026-10-07 the code sent a zero-CRC header to address 1, which
  a real outstation discards, while this page already described the
  Request Link Status (PITF-073).

## Frame validation (both proxies)

Before either proxy classifies a frame from the master side, it applies
the stateless rows of the DNP Users Group Application Note AN2013-004b,
"Validation of Incoming DNP3 Data" (revision b, 2014-08-13), Table 1:
the conditions under which an outstation's data link layer must discard
a frame (`wire.ReadFrame` + `wire.CheckToOutstation`).

- **Header invalid** (start octets, LENGTH below 5, or header CRC):
  nothing of it is forwarded and the proxy hunts for the next valid
  header octet by octet, as the note prescribes after a discard. The
  LENGTH of such a header cannot be trusted to frame anything, and a
  serial master behind a terminal server can deliver line noise inside
  TCP, so this does not end the session. (Before 2026-10-14 bad start
  octets ended it.)
- **Discarded without a reply**, as a conformant outstation discards
  it: a control octet whose PRM / FCV / function combination IEEE
  1815-2012 does not define (Test Link and Confirmed User Data need
  FCV=1; Reset Link, Unconfirmed User Data and Request Link Status need
  FCV=0; Reset of User Process, primary 1, was removed in 2012; a
  secondary frame may only be ACK, NACK, LINK_STATUS or NOT SUPPORTED);
  any frame other than user data whose LENGTH is not 5 (it carries
  data it must not carry); user data with no data; a destination in
  `0xFFF0-0xFFFB` (reserved); anything but user data to a broadcast
  address; a source in `0xFFF0-0xFFFF`; a bad block CRC.
- **Not applied**, because a proxy does not track the link state or
  know the outstation's configuration: "PRM clear while no secondary is
  expected", "secondary not a permitted response", the FCB check, and
  the outstation's own address (the offensive gate's `--dnp3-link`
  pins it instead). A secondary frame that passes is header-only, so it
  carries no application data. A frame shorter than its LENGTH is not
  discarded: on a stream the proxy waits for the rest.

Until 2026-10-14 neither proxy did this. Both forwarded every PRM=0
frame and the link functions 2 and 9 (the offensive gate also 0) with
whatever body they carried: a Direct Operate TRIP inside a frame with
control `0x84` (a "secondary function 4" that does not exist) skipped
all four layers of the offensive gate, which `proxy listen` serves,
and crossed the default write-ban handler, which no command serves yet
(see below). Whether
an outstation acted on it depended on its stack: a conformant one
discards it, and Project Robus (Crain and Sistrunk, 2013-14) disclosed
dozens of flaws in how DNP3 stacks handle malformed input. Not tested
against a real outstation (PITF-081).

## Proxy policy (default build)

No command serves this handler today: in the default build `elsereno
proxy` is a stub that exits 75 ("planned for a later phase"), and the
offensive build's `proxy listen` serves the write-gate below. The
write-ban handler is library code, covered by tests, for when a
default-build proxy command exists (open decision in `TODO-vNext.md`).

After validation, every frame's link-layer control byte is classified:

- **CategoryRead**: the header-only link replies a master returns
  (PRM=0 ACK, NACK, LINK_STATUS, NOT SUPPORTED), PRM=1 Test Link States
  (FC 2), PRM=1 Request Link Status (FC 9). Forward untouched.
- **CategoryWrite**: PRM=1 Reset Link States (FC 0), Confirmed User
  Data (FC 3), Unconfirmed User Data (FC 4). The user-data frames carry
  the application layer, so the default handler conservatively blocks
  them. Reset of User Process (FC 1, removed in IEEE 1815-2012) no
  longer reaches classification: it is an invalid frame.
- Until 2026-10-07 the table had Test Link as FC 1, so this proxy
  forwarded a Reset of User Process and refused a real Test Link; and
  it read a refused frame's body without its block CRCs, which broke
  the next frame (PITF-074). The numbering now matches Wireshark's
  `packet-dnp.c`.
- **CategoryUnknown**: any other function. Blocked (validation already
  discards them; the classifier refuses them on its own as well).

Refusal is a secondary FC 15 "Not Supported" frame with the source and
destination swapped and a correct header CRC.

## Writes (`-tags offensive`)

The offensive build replaces the `proxy` stub with `proxy listen` and
a four-layer write-gate (`offensive/write/dnp3`). Read (FC 1) always passes;
everything else is default-deny. Before the four layers it applies the
same frame validation as the default handler (above) and discards an
invalid frame without a reply. Every refusal and discard is counted,
and the first ones of a session are recorded with their reason (see
"Gate decisions in the audit chain" below).

1. **Link-layer primary FC** (`--dnp3-primary`, optional, `3` or `4`).
   By default both user-data functions pass to the application-layer
   gate; listing `3` or `4` restricts them to confirmed or unconfirmed
   user data (a Read inside the other one is refused too). Reset Link
   (0), Test Link (2) and Request Link Status (9) always pass,
   header-only, so the flag rejects them, as it rejects any function
   IEEE 1815-2012 does not define.
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

The gate judges the whole request, not the part of it that arrives
first:

- **Every object header.** A control may carry several object headers,
  and the outstation acts on all of them. Under a CROB or analog scope
  each header is checked; one the scope does not cover, a malformed one,
  or octets left over refuse the request. Until 2026-10-14 only the
  first header was read, so a TRIP in a second header behind an allowed
  LATCH passed (PITF-082).
- **Every transport segment.** A request longer than one frame travels
  as several transport segments (FIR on the first, FIN on the last).
  The gate holds the segments until the last one arrives and forwards
  or refuses them together; header-only link frames between them still
  pass. A continuation without a first segment, out of sequence or from
  another address pair is discarded and drops the held request, and so
  is a request above 2048 application octets.
- **Only a Read may span several segments.** The gate cannot know which
  segments the outstation's link layer accepts: a frame with DIR=0, a
  Confirmed User Data frame with an unexpected FCB, or a frame of
  LENGTH 6 may be dropped there. If it drops one, the segments of two
  requests can join into one the gate never judged (an allowed split
  LATCH, then a split Read whose continuation carries a TRIP). So any
  other multi-segment request is refused, even when every object in it
  is allowed, and whatever the outstation reassembles is either a
  single frame the gate judged or a Read. This rests on the outstation
  starting a fragment only with a FIR segment, as IEEE 1815 Clause 8
  requires and opendnp3 does. Cost: a control or write too long for one
  frame (about 249 application octets, some 15 to 20 CROBs) has to be
  sent as several requests.
- Until 2026-10-14 every frame was judged on its own, and the function
  code was read at the same offset of every segment, where a
  continuation carries object data: a Direct Operate split in two passed
  with only its first segment checked (PITF-082). Limit: a master that
  asks for a link confirmation of each segment of a multi-segment Read
  waits for an ACK the gate only lets through once the request is
  complete, so such a request times out [inference: link confirmation
  is normally off over TCP].

Refusal is a well-formed DNP3 response carrying IIN2.0 "function code
not supported" (`IIN2` byte `0x01`), the request's application
sequence number and correct header and block CRCs, so the master
parses it rather than seeing a wire fault, and can match it to its
request: an opendnp3 master ignores a response whose sequence differs.
The refusal stands in for the outstation's answer, so it is sent only
where an outstation would answer. A refused broadcast or NO-ACK request
(Direct Operate No Ack and the other "No Ack" functions) gets nothing,
as AN2013-004b's footnote (a) requires of an outstation; so does an
application Confirm or any other message with UNS set (a confirmation,
not a request, in the note's Table 2), and a fragment without an
application header. A
refused application Confirm is therefore dropped silently: whether the
gate should forward Confirms (they acknowledge events, and let the
outstation clear them) is an open decision. Until 2026-10-14 the
refusal set `IIN2` `0x04`, which is IIN2.2 "parameter error", always
sequence 0 (so such a master saw it only for requests numbered 0), and
went to every refused request (PITF-083). Limit: the refusal is written
on the same socket as the outstation's replies, so it can land between
two segments of a multi-segment response, and the master then loses
that response fragment. The gate reads
the full block-CRC-framed body and verifies every block CRC: a corrupt
frame is discarded.

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

## Gate decisions in the audit chain

The gate records what it does not forward. Each refusal (answered with
the IIN2.0 response, or silent where an outstation would not answer)
and each discard (a frame that fails the AN2013-004b checks or the
transport reassembly rules, a multi-segment request left unfinished
when the session ends) goes to stderr and to the audit chain as a
`dnp3_gate_decision` row with its reason, the link addresses (left out
when there was no valid link header) and the application function (-1
when there is none, as in a continuation segment). The master side
decides how many there are, so a session records the first 20 one by
one; when it ends, also when the proxy stops, one `session_summary`
row carries its totals (forwarded, which counts header-only link frames
too, refused, refused_silent, discarded, and how many were suppressed
past the first 20). A session that refused and discarded nothing
records nothing, so connections that only forward add nothing to the
chain.

The rows go through a bounded queue with one writer, so the gate never
waits on the audit file. When the queue is full a decision is dropped
and counted, and the next row written carries `dropped_before`; the
queue is flushed before the audit file closes. The 20-per-session limit
is per connection: a client that opens many connections can make the
queue fill and drop, but not block the gate.

When a flag would have allowed the request, the reason names it, for
example `application function not allowed (--dnp3-app-fc)`, `control
object outside the scope (--dnp3-control / --dnp3-analog)` or `link
address pair not pinned (--dnp3-link)`; others say what the request
was, such as `control or write to a broadcast address` or `only a Read
may span several transport segments`. The rows need database migration
00020 if the chain is mirrored to Postgres, and export like any other
event:

```sh
elsereno audit export --event-type dnp3_gate_decision --format cef
```

Until 2026-10-14 only the session opening was audited: a refusal left
no trace beyond the reply, and a discard only a stderr line.

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
| Malformed-frame abuse | a truncated frame, a bad header or block CRC, a reserved address, or a CROB with an unsupported qualifier | Both proxies apply the stateless rows of AN2013-004b Table 1: an invalid frame is discarded without a reply and an invalid header is skipped until the next valid one; a malformed control is refused, not forwarded |
| Request smuggling | an application request inside a frame whose link function carries no data (PRM=0, Request Link Status, Test Link, Reset Link) | Discarded before classification since 2026-10-14; until then it crossed the offensive gate and the default write-ban handler (PITF-081) |
| Request splitting | an allowed control followed by a forbidden one in a second object header, or a control split across transport segments | The gate judges the whole request (every header, every segment) since 2026-10-14; until then both passed with only the first part checked (PITF-082) |

Note the asymmetry the poster stresses: reads forward (a passive tap
must not break the process it observes), controls and writes are
default-deny, and the single byte that carries the intent (the CROB
control code) is inspected, not waved through with the function code.

## Scope

- DNP3 outstations at power-utility RTUs, DER inverters, reclosers, and
  substation IEDs; a control here throws a physical breaker.
- The link-layer probe carries no application-layer request and changes
  no outstation state (Request Link Status asks for the link status; it
  does not reset the link). It is not invisible on the network: see the
  footprint under Probe. (Until 2026-10-14 this page called it
  "invisible to most deployed DNP3 RTUs".)

## Public references

- IEEE Std 1815-2012; the DNP Users Group object library.
- DNP Users Group, Application Note AN2013-004b "Validation of Incoming
  DNP3 Data" (2014-08-13):
  <https://www.dnp.org/Portals/0/Public%20Documents/DNP3%20AN2013-004b%20Validation%20of%20Incoming%20DNP3%20Data.pdf>
- Pascal Ackerman, "DNP3 Attack & Defend" poster, v1.0, September 2026,
  CC BY 4.0:
  <https://github.com/SackOfHacks/OT_Security_OnePagers/tree/main/DNP3>
- NIST SP 800-82r3; NERC CIP-005 / CIP-007.
- Wireshark DNP3 dissector (`packet-dnp3.c`); CISA/INL ICSNPP-DNP3.
