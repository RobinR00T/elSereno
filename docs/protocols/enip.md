# EtherNet/IP / CIP (port 44818)

EtherNet/IP is the ODVA family of protocols built on Common
Industrial Protocol (CIP) encapsulation. Allen-Bradley ControlLogix
/ CompactLogix, Schneider M580, Phoenix Contact ILC, Omron NJ, and
many others speak it.

## Probe

- Send `ListIdentity` (command 0x0063) with an empty body.
- Parse the response's Identity CPF item: VendorID, DeviceType,
  ProductCode, Revision, Status, SerialNumber, ProductName.

Capability score jumps when the target returns a well-formed
identity item.

## Proxy policy (default build)

The encapsulation command is classified per wire table:

- **CategoryRead** — ListServices (0x04), ListIdentity (0x63),
  ListInterfaces (0x64), RegisterSession (0x65), UnregisterSession
  (0x66). Forward untouched.
- **CategoryWrite** — SendRRData (0x6F), SendUnitData (0x70). Both
  envelope CIP service requests that can mutate state; short-
  circuited with an encapsulation status of 0x0001 ("Invalid or
  unsupported command").

Service-level classification (CIP SetAttributeSingle vs.
GetAttributeSingle) lives in the offensive-build `WriteGatedHandler`
and ships in F6+.

## Writes (`-tags offensive`)

`offensive/write/enip`:

| Op                         | CIP service | Typical target                       |
|----------------------------|-------------|--------------------------------------|
| `set_attribute_single`     | 0x10        | class / instance / attribute write   |
| `reset`                    | 0x05        | Identity object (class 0x01/inst 1)  |

## CIP service-code detection surface (class-scoped)

`internal/protocols/enip/wire/cipservice.go` labels a CIP service byte
by its operational impact (read, connection, write, admin) for the
detection / scoring path. It does not touch the wire: it is a signature
table, the same role Zeek ICSNPP or a Suricata rule plays.

Two rules keep it honest:

- **Class-scoped matching.** A CIP service code means different things
  depending on the object class it addresses. `0x52` is
  `Unconnected_Send` in the Connection Manager (class 0x06) but Read Tag
  Fragmented against the Symbol object (class 0x6B); `0x4E` is
  `Forward_Close` in the Connection Manager but Read-Modify-Write Tag (a
  write) against Symbol. Matching the byte with no class context is the
  classic false positive, so `ClassifyCIPService` returns whether the
  verdict was actually class-scoped. Scoring down-weights, never drops,
  an unscoped write/admin hit.
- **False-zero rule.** A zero write count is only clean if we had
  visibility. `ServiceObservation.Verdict()` returns `blind` (not
  `clean`) when no service of any kind was seen, `clean` only once a
  read or a Forward_Open proves the vantage point would have caught a
  write, and `active` on any write or admin (Reset / Stop / Start).

| CIP service        | Code | Kind vs class                                  |
|--------------------|------|------------------------------------------------|
| Get Attribute(s)   | 0x01, 0x0E | read (class-independent)                 |
| Set Attribute(s)   | 0x02, 0x10 | write (class-independent)                |
| Reset/Start/Stop   | 0x05/0x06/0x07 | admin (device state change)          |
| Read Tag           | 0x4C | read @ Symbol/Template                          |
| Write Tag          | 0x4D | write @ Symbol/Template                         |
| `0x4E`             | 0x4E | connection @ ConnMgr, write @ Symbol            |
| `0x52`             | 0x52 | connection @ ConnMgr, read @ Symbol             |
| Forward_Open       | 0x54, 0x5B | connection (visibility signal)           |

## Related exploit

**CVE-2019-10953** (ships in `offensive/exploits/cve_2019_10953`)
abuses the encapsulation Length over-read. Affects Schneider M580,
Allen-Bradley ControlLogix 5380/5580, and Phoenix Contact ILC/AXC.

## Public references

- ODVA Common Industrial Protocol Vol 1 + Vol 2.
- CISA ICSA-19-122-02.
- Pascal Ackerman, CIP one-pager (2026): service-code detection surface,
  class-scoped matching and the false-zero rule. Companion material:
  `github.com/SackOfHacks/OT_Security_OnePagers/tree/main/CIP`.
