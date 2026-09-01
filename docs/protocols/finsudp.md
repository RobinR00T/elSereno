# Omron FINS UDP (port 9600)

FINS (Factory Interface Network Service) is the OMRON-specific
factory automation protocol that ships on every CJ / CS / CP / NJ /
NX series CPU and most OMRON HMIs. UDP/9600 is the default
transport; TCP/9600 and serial framings exist but UDP is by far
the most common Internet-exposed shape (Shodan dorks: `port:9600
fins`, `omron`, `cpu`).

## Probe

- Send the 13-byte CONTROLLER DATA READ datagram (MRC=0x05,
  SRC=0x01, area=0x00). The frame layout is from OMRON CPU manual
  W421 §5.1 / §5.4.
- Expect a response with the FINS response-bit set (ICF=0xC0), the
  same SID echoed in byte 9, MRC=0x05, SRC=0x01, end code
  0x0000 (success), then a 60-byte controller-data block:
  - 20-byte ASCII Model (e.g. "CJ2M-CPU33", "NJ501-1500")
  - 20-byte ASCII Internal Code (vendor-internal version)
  - 20-byte ASCII System Version (newer CPUs only)
- The Model field is folded into the finding hash so dedup is
  per-controller-model.

The probe is idempotent and side-effect-free: CONTROLLER DATA READ
does not touch memory areas or registers — it returns the CPU's
self-description.

## Wire layout

```
Offset  Field  Size  Description
0       ICF    1     0x80 (request) / 0xC0 (response)
1       RSV    1     0x00
2       GCT    1     0x02 (direct)
3       DNA    1     0x00 (same network)
4       DA1    1     0x00 (broadcast/direct)
5       DA2    1     0x00 (CPU)
6       SNA    1     0x00
7       SA1    1     0x01 (caller node)
8       SA2    1     0x00
9       SID    1     Service ID (echoed in response)
10      MRC    1     0x05 (Controller Data Read)
11      SRC    1     0x01 (all)
12      data   …     0x00 = entire block (request); end code +
                     model + internal + system (response)
```

## Proxy policy (default build)

FINS is **UDP**, so the generic TCP proxy framework cannot
legitimately relay datagrams. In the default build
`finsudp.ProxyHandler()` returns an immediate error so operators
don't accidentally shuttle bytes that aren't FINS. The write-gated
UDP relay lives in the offensive build (see below); the proxy
framework drives it over the new UDP transport (`Options.Network`,
shared with iax2).

## Writes (`-tags offensive`)

Shipped. The write-gated UDP proxy lives in
`offensive/write/finsudp` (ADR-040 template, mirrors the knxip
UDP handler). Per-datagram classification at wire-parse time:
reads (Memory Area Read, Controller Data Read, Clock Read, ...)
always pass; a mutating command is admitted only when the operator
allowlisted its exact `(MRC, SRC)`.

```sh
# 1) Mint the session confirm-token (ADR-039 triple-confirm):
elsereno-offensive write finsudp proxy-dry-run \
  --target plc.internal:9600 \
  --fins-command 0x01:0x02 \       # Memory Area Write
  --fins-command 0x04:0x01 \       # RUN
  --fins-area 0x82 \               # optional: narrow the write to DM (0x82), CIO (0xB0), ...
  --vault-passphrase-file ~/.elsereno/dev.pp

# 2) Run the gated proxy (UDP/9600) with the triple-confirm fence:
elsereno-offensive proxy listen --plugin finsudp \
  --listen 127.0.0.1:9600 --target plc.internal:9600 \
  --fins-command 0x01:0x02 --fins-command 0x04:0x01 --fins-area 0x82 \
  --accept-writes --confirm-target plc.internal:9600 \
  --confirm-token <token-from-dry-run> \
  --vault-passphrase-file ~/.elsereno/dev.pp
```

Flags: `--fins-command MRC:SRC` (byte pair, decimal or `0x..`,
repeatable) and `--fins-area <byte>` (optionally narrows an allowed
Memory Area Write to specific area codes; empty = any area).

**Refusal semantics**: a refused datagram gets a **native FINS
response** (end code `0x2101`, "cannot write / write-protected")
written back to the client and never forwarded upstream, so an
intelligent client sees an intelligible error rather than a silent
drop (ADR-040). The wire parser + area codes come from
`internal/protocols/finsudp/wire` (OMRON W421). Triple-confirm +
audit-chain emission per ADR-039.

Out of scope for this cycle: per-address narrowing within an
allowed Memory Area Write (the FINS analogue of the knxip
group-address tier).

## Scope

- OMRON CPUs (CJ1/CJ2/CS1/CP1/NJ/NX series) on factory floors,
  packaging lines, food-and-beverage, automotive plants.
- Compatible HMIs (NS / NB / NA series) and SCADA gateways.
- Impact: a writeable FINS endpoint can stop a CPU (RUN→STOP),
  force an output bit, or rewrite a program memory file — direct
  effect on the factory floor.

## Public references

- OMRON CPU Manual W421 (FINS Commands Reference) — canonical
  protocol reference.
- ICS-CERT advisories on OMRON CJ/CS lacking authentication
  (multiple, 2015-onwards).
- Industroyer / Industroyer2 IOC analyses — similar legacy-ICS
  pattern (no auth, model-string fingerprinting works on
  Internet-exposed CPUs).
