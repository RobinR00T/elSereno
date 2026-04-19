# Banner / dictionary

The `banner` plugin is the low-effort catch-all — read the first
bytes of a TCP connection, look for vendor-specific ASCII markers,
emit a finding with a vendor label. It complements the protocol-
aware plugins for ports that do not carry one of the specialised
protocols.

## Targets

- Serial-server products (Moxa NPort, Lantronix, Digi, NetBurner).
- Elevator control systems (KONE, Otis, Schindler).
- OpenSSH banners on non-standard ports.

## Probe

- Open TCP, read up to 8 KiB for up to the IO timeout.
- Match the read bytes against the vendor dictionary in
  `internal/protocols/banner/vendors.go`.

Match rules are case-insensitive substring matches. A known-good
vendor string bumps the finding score.

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
