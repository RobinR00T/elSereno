% ELSERENO-SCOPE(5) ElSereno scope file | File formats
% ElSereno project
% 2026-04-19

# NAME

**scope.yaml**: authorised scope file for *elsereno*(1)

# DESCRIPTION

A *scope.yaml* file defines the authorised ranges, ports and protocols,
and the dialling blacklist, for an engagement. It also accepts web binds
and a canary, which are parsed but not applied.

A scope file applies only when passed with **--scope**. Every command
that connects to a target takes it: **scan**, **serve** (dashboard,
API and schedule scans), **discover**, **fingerprint probe**,
**plaintext-check**, **tui --input**, **opcua probe-anon** and
**probe-write**, **s7 probe**, **probe-protection** and
**probe-identity**, and in the offensive build **write modbus send**,
**exploit run**, **proxy listen**, **harvest** and **creds-check http**,
plus **dial** (which applies only **dial.blocked_numbers**).
**lint --scope** only validates it. Until 2026-10-17 only **scan**,
**serve** and **dial** took it. Nothing loads it on its own: a
*scope.yaml* in the working directory is not read, and without
**--scope** nothing is filtered. A file that does not parse stops the
command with exit 78. Keys other than the ones below are a parse error.

# FORMAT

```yaml
version: 1
ranges:
  - cidr: 192.168.0.0/16
    note: "internal lab"
  - cidr: 2001:db8::/32
    note: "ipv6 lab"
ports:
  allow: [502, 102, 44818, 47808, 2404, 20000, 1998, 9999]
  deny: []
protocols:
  allow: [modbus, s7, enip, bacnet, dnp3, iec104, xot, atmodem, banner]
  deny: [s7-exposure]
binds:
  allow:
    - 127.0.0.1:8787
    - "[::1]:8787"
dial:
  # In addition to the hardcoded ≤3-digit block (always on).
  # Digits only, no "+" or leading "00": entries are not normalised.
  blocked_numbers:
    - "34112"
    - "34062"
canary:
  enabled: false
  alert_webhook: ""
```

# SEMANTICS

**ranges**
:   CIDRs, IPv4 and IPv6. With no entries, any address passes. With
    entries, a target outside all of them is dropped before any
    connection. A malformed CIDR is skipped without error, so what only
    it covered is dropped.

**ports.allow / ports.deny**
:   Deny wins over allow. If **allow** is empty, all ports are allowed
    subject to **deny**.

**dial.blocked_numbers**
:   Numbers refused by **dial**, exact or as a prefix, on top of the
    hard-coded block of numbers of 3 digits or fewer. **dial** normalises
    the dialled number (drops "+", a leading "00" and punctuation) but
    not the entries, so write them as digits only: "+34112" or
    "0034112" block nothing.

**protocols.allow / protocols.deny**
:   Which plugins may run. An entry matches a plugin's name or its
    protocol, the part of the name before the first "-": **s7** covers
    s7 and s7-exposure, **s7-exposure** only that plugin, and
    **opcuahttps** is a name of its own. Case is ignored. Deny wins
    over allow; an empty **allow** lets through every plugin not
    denied, and a non-empty one must list **banner** for banner to
    run. A plugin named with **--plugin** (or in a dashboard job) that
    the lists refuse stops the scan (exit 77, or a failed job); without
    names the refused plugins are left out, and **scan** says which on
    stderr. **discover** does not sweep the ports of refused plugins.
    The verbs count as a plugin: **opcua probe-anon** and
    **probe-write** as opcua-exposure, the three **s7** probes as
    s7-exposure, **harvest** as its sub-verb (telnet, ftp, http-basic,
    snmp), **creds-check http** as http-basic, **write modbus send** as
    modbus and **proxy listen** as its **--plugin**. **exploit run**
    and **plaintext-check** name no plugin, so only ranges and ports
    apply to them. Families go by name only: **deny: [s7]** does not
    cover **mms**, which also speaks COTP on port 102; list it too.
    An entry that matches no plugin (a typo such as **s7-**) changes
    nothing and no command warns about it.

**binds.allow**
:   Parsed, not applied. A non-loopback bind of **serve** is governed by
    its own flags (**--tls-cert**, **--tls-key**,
    **--i-know-what-im-doing**).

**canary**
:   Parsed, not applied.

**ranges** and **ports** apply to the address and port each command
connects to. A command with a list (**scan**, **serve**, **discover**,
**tui --input**) drops what falls outside; a command with one
**--target** refuses it with exit 77 before connecting. A read-only
command given a name resolves it once, checks that address and
connects to it, so the name cannot resolve elsewhere after the check;
**creds-check http** does the same and keeps the name in the Host
header. **write modbus send**, **exploit run** and **proxy listen**
need **--target** as an IP:port with **--scope** (exit 64 otherwise):
their confirm token covers the target as typed.

A dropped target is not probed and leaves no trace: there is no
per-target message and no audit event. When no target is left, **scan**,
**discover** and **tui --input** exit with 66.

# SEE ALSO

*elsereno*(1), *elsereno.yaml*(5), *elsereno-security*(7).
