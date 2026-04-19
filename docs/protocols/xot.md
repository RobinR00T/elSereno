# XOT (X.25 over TCP, port 1998)

XOT (RFC 1613) carries classic X.25 packets inside a 4-byte TCP
envelope. Remnant from the 1990s — still deployed as the
communications layer for legacy SCADA gateways, financial transport,
and airline reservation systems. Finding a live XOT responder in
2026 is a strong signal that the target has legacy infrastructure
worth auditing carefully.

## Probe

- Open TCP to port 1998.
- Send an X.25 Call Request packet wrapped in the 4-byte XOT header
  (Version 0x0000 + Length big-endian).
- Parse the response's X.25 PTI (Packet Type Identifier):
  - `0x0B` Call Accepted — a live X.25 endpoint exists.
  - `0x13` Clear Request — reachable but rejecting the SVC.
  - Silent close — not XOT.

## Proxy policy (default build)

Pass-through with filtering — the proxy reads each 4-byte XOT
header, validates Version=0 and Length ≤ 4096, and forwards valid
frames. Frames outside spec are dropped without closing the session.

The per-packet classifier (distinguishing a CLEAR from a DATA
packet) lives in the F5 framework but is not yet wired into a
wire-layer refusal.

## Writes (`-tags offensive`)

Deferred to F6+. X.25 does not have a traditional "write" primitive;
the equivalent offensive operation is a CLEAR Request or a DATA
packet carrying PAD X.29 commands. Both land behind triple-confirm.

## Scope

- Legacy SCADA gateways (utilities, railways).
- Financial transport networks (SWIFT has migrated, but
  pre-SWIFTNet bridges remain).
- Airline reservation and cargo tracking.

## Public references

- RFC 1613 "XOT" (1994).
- ITU-T X.25 Recommendation.
