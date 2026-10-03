# Exposure auditing (read-only)

This guide covers ElSereno's **active exposure probes**: the commands that
go past a banner fingerprint and confirm, on the wire, whether an OT device
is actually exposed (writable without a password, reachable anonymously,
speaking in cleartext). Everything in this guide except the clearly-marked
`creds-check` is **strictly read-only**: these probes read state, they never
write, control, or stop a device.

Where a fingerprint says "this looks like an S7 PLC", an exposure probe
says "...and a stranger can change a tag on it without a password". That is
the difference between a reachable service and a confirmed exposure.

## How these differ from `scan` / `discover`

`scan` and `discover` sweep the default fingerprint plugins. The deep
exposure probes are **not** in that sweep: the per-protocol ones are
dedicated subcommands (`s7 probe`, `opcua probe-anon`, ...), and the scored
variants are **opt-in plugins** with `DefaultPort 0`, so they run only when
named with `--plugin`. This keeps the default sweep fast and conservative,
and makes every deep probe an explicit operator choice.

## S7 (Siemens, port 102)

One-shot posture, the command to run first:

```sh
elsereno s7 probe --target plc:102 --json
```

It reads, over a single handshake, what the CPU is (order number / MLFB,
firmware, module type, serial) and whether it accepts writes/control
without a password. The focused variants are `s7 probe-protection` (just
the protection level) and `s7 probe-identity` (just model + firmware).

What the protection level means: effective level **1** (or 0/undefined) is
the exposure, a stranger can write tags or control the PLC; **2** is
write-protected; **3** is read+write protected. See
[`protocols/s7.md`](protocols/s7.md) for the SZL wire detail. The S7 wire
is validated **byte for byte against a real captured S7-300 session**.

As a scored `core.Finding` (opt-in plugin):

```sh
elsereno fingerprint probe --plugin s7-exposure --target plc:102 --json
```

A CPU writable without a password scores Critical. When the CPU's MLFB
order number identifies a family with curated real CVEs (e.g. an S7-1500
carries CVE-2020-15782), the `s7-exposure` finding raises its `cve_exposure`
score and records the CVE ids in its note. This is a **family-level**,
non-exhaustive match (`internal/cve`), not a firmware-exact lookup: pair it
with NVD / the vendor advisory for the precise firmware. ET200 distributed
CPUs are deliberately not classified (the MLFB is ambiguous), so they get
no CVE boost rather than a wrong one.

## OPC UA (port 4840)

Confirm anonymous access actually opens a session (not just that the
endpoint advertises it):

```sh
elsereno opcua probe-anon --target plc:4840 --json
```

Then walk the address space for what that anonymous stranger could change:

```sh
elsereno opcua probe-write --target plc:4840 --max-nodes 500 --json
```

`probe-write` reads the `UserAccessLevel` attribute of each variable and
flags the ones carrying the `CurrentWrite` bit. It is strictly read-only:
it reads attributes, it never issues a Write. The walk is bounded by
`--max-nodes` so a large or hostile address space cannot run away.

As a scored `core.Finding` (opt-in plugin):

```sh
elsereno fingerprint probe --plugin opcua-exposure --target plc:4840 --json
```

An anonymous session that opens is High; one that also exposes
anonymous-writeable control-plane tags is Critical. See
[`protocols/opcua.md`](protocols/opcua.md) for the session and
Browse/Read wire detail and its validation caveat.

## Cleartext transport (any service)

```sh
elsereno plaintext-check --target plc:502 --json
```

This actively tests whether a reachable service negotiates TLS. If it does
not, the transport is cleartext: credentials and process data cross the
wire in the clear. The check reports the protocol (by port), whether TLS
was negotiated and at what version, and the secure alternative where one
exists. Read-only: it opens a connection and attempts a TLS handshake, it
sends no application-layer payload.

## Default credentials (offensive build, authorized use only)

> **AUTHORIZED USE ONLY.** This check sends authentication attempts to a
> target. Run it only against infrastructure you are authorized to test.
> It lives in the `elsereno-offensive` binary and refuses to run without
> `--confirm-authorized`.

```sh
elsereno-offensive creds-check http \
  --target https://plc-hmi.internal \
  --confirm-authorized --json
```

It verifies a small set of **published** vendor default credentials (the
ones documented in vendor product manuals) against a device web UI's HTTP
Basic auth. It fetches a baseline first and only tests when the endpoint
actually challenges (401/403); it is not a brute-force tool and carries no
password lists beyond the documented defaults.

## Standards traceability

Every finding traces to the NIST SP 800-82 Rev. 4 vulnerability it
evidences. Print the catalog:

```sh
elsereno standards --protocol opcua-exposure
```

The mapping rides through every output surface except CSV: the ndjson
output (a `standards` array per finding), the HTML report (a per-protocol
block), the GitHub Issues / Jira sinks (issue body + a filterable
`standard/...` label), the CEF / syslog writers (CEF `cs3`, a syslog
`standard` structured-data param) for SIEM ingest, the STIX 2.1 bundle
(native `external_references`), and the webhook envelope (a `standards`
array). See [`standards/nist-sp800-82r4.md`](standards/nist-sp800-82r4.md).

## Read-only guarantee, in one place

| Command | Writes to target? |
|---------|-------------------|
| `s7 probe` / `probe-protection` / `probe-identity` | No (reads SZL diagnostic lists) |
| `s7-exposure` plugin | No (reuses the posture read) |
| `opcua probe-anon` | No (opens a session, reads nothing) |
| `opcua probe-write` | No (reads node attributes) |
| `opcua-exposure` plugin | No (reuses the anon + walk read) |
| `plaintext-check` | No (TLS handshake only, no payload) |
| `creds-check http` | **Sends auth attempts** (offensive build, authorized only) |

## Not covered here

ENIP (EtherNet/IP) and Modbus device-identification hardening against real
captured bytes is **blocked** on capture availability (the specific
exchanges, ListIdentity 0x63 and Modbus FC43/14, are not in the public ICS
pcap sets accessible to this project). It is tracked in `TODO-vNext.md` and
will not ship on fabricated fixtures.
