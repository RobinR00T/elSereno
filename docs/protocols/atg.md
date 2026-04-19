# ATG Veeder-Root (port 10001)

Veeder-Root ATG (Automatic Tank Gauge) — TLS-350 / TLS-4 — monitors
fuel-tank levels for gas stations. Port 10001 is TCP and unbypassed
in many deployments. Internet-exposed ATGs have featured in multiple
published security research efforts.

## Probe

- Send the SOH-framed I20100 command: `\x01I20100\r\n` (system
  status query).
- A response beginning with `\x01` and the printable tank-data block
  confirms an ATG. The probe parses station name, tank id, volume,
  ullage, temperature.

## Proxy policy (default build)

Line-oriented ASCII, SOH-framed. The proxy reads one command line
at a time (up to 4 KiB or CR, whichever first) and classifies:

- **CategoryRead** — lines starting with `I` (Info family: I20100
  system status, I10200 product code summary, I20200 tank volume
  history, etc.). Forward.
- **CategoryWrite** — everything else: `V` (setpoint), `S` (set
  configuration), `T` (tank calibration), etc. Refused in-band.

Refusal is the Veeder-Root `9999FF1B\r\n` "Data Error" response —
the closest the protocol has to a protocol-native "refused" frame.

## Writes (`-tags offensive`)

Deferred to F6+. The offensive ATG plugin will route V/S/T commands
through triple-confirm.

## Scope

- Gas station fuel dispensers + pump controllers.
- Airport / military fuel depots.
- Impact: incorrect readings can cause over-pumping or alarm
  suppression. A mis-set alarm threshold can delay spill detection.

## Public references

- Veeder-Root TLS-350 Operator Manual (public).
- Rapid7 "The Internet of Gas Station Tank Gauges" (2015).
- CVE-2019-3992 (not ElSereno-implemented) for a specific ATG auth
  bypass.
