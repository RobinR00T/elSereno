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

## Related exploit

**CVE-2019-10953** (ships in `offensive/exploits/cve_2019_10953`)
abuses the encapsulation Length over-read. Affects Schneider M580,
Allen-Bradley ControlLogix 5380/5580, and Phoenix Contact ILC/AXC.

## Public references

- ODVA Common Industrial Protocol Vol 1 + Vol 2.
- CISA ICSA-19-122-02.
