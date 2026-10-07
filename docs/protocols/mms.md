# IEC 61850 MMS (TCP 102)

MMS (ISO 9506) over the OSI stack (TPKT, COTP, ISO 8327 session,
ISO 8823 presentation, ACSE) is how IEC 61850 clients talk to
substation IEDs (protection relays, RTUs, merging units). It shares
TCP/102 with S7comm; the `mms` and `s7` plugins tell them apart by
their COTP TSAPs.

## Probe

1. COTP Connection Request with the MMS TSAPs (0x0001 / 0x0001). A
   Connection Confirm already identifies an ISO-transport speaker
   (positive finding).
2. ACSE AARQ, byte for byte the real client AARQ of the w3h/icsmaster
   IEC 61850 captures (session CONNECT, presentation CP, ACSE AARQ
   for application context 1.0.9506.2.3, and the MMS
   Initiate-RequestPDU). The AARE's application-context OID identifies
   an IEC 61850-8-1 stack; its result field says whether the
   association was accepted (a rejection is noted as such).
3. On an accepted association only: GetServerDirectory (getNameList,
   object class domain, vmd-specific scope) wrapped in session
   Give-Tokens + Data and a presentation P-DATA, as every
   post-association PDU must be; the reply is unwrapped and the
   Logical Device names are read.

Until 2026-10-07 the AARQ carried no Initiate-RequestPDU and the
directory request went out without the session/presentation layers
and with a malformed NULL, so the deep part never worked against a
real server (PITF-077).

The vendor hint and the LD list are hashed into the finding ID; they
are not printed (a finding has no field for them; open decision in
TODO-vNext).

## Proxy

Default build: fail-closed (no MMS-aware read classifier). Offensive
build: `proxy listen --plugin mms` (gated).

## Validation

`docs/parser-validation.md`: AARE parser, AARQ and getNameList checked
against w3h/icsmaster `iec61850_read.pcap` and
`iec61850_get_name_list.pcap`.
