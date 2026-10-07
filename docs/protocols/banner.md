# Banner / dictionary

The `banner` plugin is the low-effort catch-all: read the first bytes
of a TCP connection and emit a low-score finding that the port is open
(with or without a banner). It has no default port, so `scan` runs it
on every target; `discover` does not sweep for it.

The vendor dictionary below (`DetectVendor`) exists but the probe does
NOT apply it today: the finding carries no vendor label and its score
is fixed (28, low), and the banner text itself is not in the output
(a `core.Finding` has no field for it; an open decision in
TODO-vNext).

## Targets

- Serial-server products (Moxa NPort, Lantronix, Digi, NetBurner).
- Elevator control systems (KONE, Otis, Schindler).
- OpenSSH banners on non-standard ports.

## Probe

- Open TCP and read up to 16 KiB until the read timeout (5 s); a
  silent port still yields a finding with an empty banner.
- The finding ID covers the address, port and banner bytes.

`vendors.go` holds case-insensitive substring matchers for the
targets above, used by tests only until the probe is wired to them.

## Vendor dictionary

| Vendor         | Substring match                  |
|----------------|----------------------------------|
| Moxa NPort     | `Moxa NPort`                     |
| Lantronix      | `Lantronix`                      |
| Digi           | `Digi Connect`, `PortServer`     |
| NetBurner      | `NetBurner`                      |
| KONE           | `KONE`                           |
| Otis           | `Otis`                           |
| Schindler      | `Schindler`                      |
| OpenSSH        | `OpenSSH_`                       |

Updates to this list land via PR; see `.context/protocols/banner.md`
for the canonical engineering notes.

## Proxy

No proxy handler. The banner plugin is fingerprint-only.

## Scope

- Internet-exposed serial servers bridging to ICS / OT networks.
- Elevator remote-monitoring endpoints (often AT modem or HTTP).
- Unknown-service discovery.
