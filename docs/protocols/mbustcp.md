# M-Bus over TCP (port 10001)

M-Bus (Meter Bus, EN 13757-3 + EN 13757-4) is the dominant
European smart-meter protocol — water, gas, heat, electricity
meters and heat-cost allocators. M-Bus over TCP wraps the wired
M-Bus frame format; common deployments use TCP/10001 (Relay GmbH
+ Solvimus gateways), with TCP/8888 and TCP/2055 also seen.

## Probe

- Send the 5-byte REQ_UD2 short frame to broadcast primary
  address 0xFE: `0x10 0x5B 0xFE 0x59 0x16`.
- Expect either:
  - A single-byte ACK `0xE5` (the meter responded but had no
    queued data) — sufficient for fingerprinting.
  - A long-frame RSP_UD (CI=0x72) carrying the BCD ID +
    3-letter manufacturer code + medium byte + version. The
    manufacturer code + medium are folded into the finding
    hash for richer dedup.

## Wire layout

```
Long frame:                     Short frame:
  Offset Field      Value         Offset Field   Value
  0      Start      0x68          0      Start   0x10
  1      L          ...           1      C       (control)
  2      L (echo)   ...           2      A       (address)
  3      Start      0x68          3      CS      C+A mod 256
  4      C          (control)     4      Stop    0x16
  5      A          (address)
  6      CI         0x72 = var data response
  7..10  ID         4 bytes BCD
  11..12 Manuf      packed letters
  13     Version
  14     Medium     0x07 = water, 0x03 = gas, ...
  15     AccessNo
  16     Status
  17..18 Signature
  19..N  data records
  N+1    CS         sum of [4..N] mod 256
  N+2    Stop       0x16

Single-byte ACK: 0xE5
```

Manufacturer code: 3 ASCII letters packed into 16 bits. Encoded
as `M = (c1-'A'+1)*32^2 + (c2-'A'+1)*32 + (c3-'A'+1)`. Common
values: 0x0442="ABB", 0x2C2D="KAM" (Kamstrup), 0x1593="ELS"
(Elster), 0x4D2D="SEN" (Sensus).

## Proxy policy (default build)

Wire-layer write-ban. The default-build handler reads the first
M-Bus frame from the client and replies with a single-byte ACK
(0xE5) without forwarding to upstream. Matches the protocol's
own link-layer ACK idiom — the meter reports nothing went wrong
but no data is returned, which is the closest thing to "request
denied" in M-Bus.

## Writes (`-tags offensive`)

Deferred. M-Bus write services include:
- `SND_UD` (CI=0x51 / 0x52) — write meter parameters: tariff
  rates, primary address, encryption keys, billing cycles.
- `SET_BAUDRATE` (CI=0xB8..0xBC) — re-baud the meter to a non-
  standard rate (a DoS-y attack: makes the meter unreachable
  to legitimate billing systems).

A future offensive plugin would gate per-(meter address,
service code) and emit `audit-chain` events per SND_UD. Triple-
confirm + audit-chain emission per ADR-009.

## Scope

- Smart meters in residential, commercial, district-heating
  networks across Europe.
- Compatible heat-cost allocators (Brunata, Ista, Techem) in
  apartment-building heating cost allocation.
- Impact: a writeable M-Bus endpoint can manipulate billing
  meter readings (consumer fraud / utility loss), invalidate
  encryption keys (locks legitimate billing systems out), or
  re-baud the meter (DoS).

## Public references

- EN 13757-3: M-Bus application layer.
- EN 13757-4: Wireless M-Bus (informational; this plugin is
  wired-over-TCP).
- "M-Bus: A documentation" v4.8 (Rev. 4.8, 2007) — public
  community reference.
- Mantz / Roecher "Insecurity of meter protocols" (CCC 2014).
