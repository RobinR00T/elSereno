---
phase: v1.22
status: implemented
last-updated: 2026-04-29
token-budget: 700
protocol-name: redlion
default-port: 789/tcp
---

# Red Lion Crimson v3 (CR3)

## TL;DR
ElSereno's `redlion` plugin connects to TCP/789 and reads the
manufacturer and model registers with the two frames of
cr3-fingerprint.nse (`00 04 01 2B 1B 00`, `00 04 01 2A 1A 00`),
classifying a CR3 string response, with the canonical Red Lion /
Crimson / Sixnet banner substrings as fallback. Until 2026-10-07 it
waited for a connect banner and sent three zero bytes (PITF-079).

## Spec references
- ICS-CERT ICSA-21-103-01, ICSA-22-088-01.
- internetofallthethings/cr3-nmap `cr3-fingerprint.nse` (the identity
  reads) and cr3-wireshark `cr3.lua` (the frame layout).
- praetorian-inc/nerva `pkg/plugins/services/crimsonv3` (same reads).
- Red Lion Crimson 3 product manuals (registration required).

## Wire format
CR3: length (2, BE, counts the bytes after itself) + register (2) +
payload (type (2) + data). `wire.ParseStringResponse` reads an identity
string after the 6-octet header.

## Fingerprint strategy
1. Send the manufacturer read, read the reply, classify (CR3 string
   first, banner substring second; an echo of the read is rejected).
2. On a positive reply, send the model read on the same connection and
   add `model=` to the note (best effort).

Substring matches: 12 canonical strings ordered most-specific
first (Red Lion Controls > Red Lion, Crimson 3 > Crimson 2,
etc.) so the matched substring in the finding note is
informative.

## Read operations (default build)
- `probe`: dial → manufacturer read → classify → model read.

## Write / dial operations (offensive build tag)
Shipped (`offensive/write/redlion`, TCP/789). CR3 is length-
prefixed (2-byte big-endian body length), so the handler reads
discrete frames and gates each by its Type opcode (offset 4).
Reads (`0x1b00` mem-read, `0x1700` poll) pass; a mutating opcode
is admitted only via `--redlion-type <u16>` (e.g. `0x1500`
config/firmware chunk, `0x1300` value write). The public dissector
(cr3-wireshark) does not authoritatively label every opcode
read-vs-write, so the auto-pass set is deliberately narrow and
everything else (handshake included) is refused unless allowlisted;
no fabricated semantics. Refusal closes the connection (fail-
closed). See `docs/protocols/redlion.md` +
`scripts/demo-redlion-proxy.sh`. ADR-039.

## Proxy hooks
Fail-closed. RLN TLV stack not implemented in chunk 3.

## Scoring contribution
factors{protocol_risk:75, exposure:75, auth_state:85, capability:30
(70 on Red Lion reply), impact_class:70, cve_exposure:5}.
- protocol_risk 75 (vs 80 PLCs), HMI/RTU rather than direct PLC.
- impact_class 70, HMI screen forge + tag forcing + firmware push.
- cve_exposure 5, ICSA-21-103-01 (hardcoded crypto key) +
  ICSA-22-088-01 (path traversal); smaller than CoDeSys's 10
  but non-zero.

## Sentinel errors (wire package)
- ErrShortFrame: < 4-byte response.
- ErrNotRedLion: response is neither a CR3 string nor carries a
  canonical banner substring.
- ErrNotCR3String: (ParseStringResponse) not a complete CR3 frame
  with a printable string.
