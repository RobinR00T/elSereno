% ELSERENO-SCOPE(5) ElSereno scope file | File formats
% ElSereno project
% 2026-04-19

# NAME

**scope.yaml**: authorised scope file for *elsereno*(1)

# DESCRIPTION

A *scope.yaml* file defines the authorised ranges and ports, and the
dialling blacklist, for an engagement. It also accepts protocols, web
binds and a canary, which are parsed but not applied.

A scope file applies only when passed with **--scope** (to **scan**, to
**serve** for dashboard scans, and to **dial** in the offensive build;
**lint --scope** only validates it). No other command takes it, so it
does not limit **discover**, **fingerprint probe**, **plaintext-check**,
**tui --input**, the per-protocol verbs, or the offensive **write**,
**exploit**, **proxy listen**, **harvest** and **creds-check**.
Nothing loads it on its own: a *scope.yaml* in the working directory is
not read, and without **--scope** no target is filtered. Keys other
than the ones below are a parse error.

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
  deny: []
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
:   Parsed, not applied: they do not limit which plugins run.

**binds.allow**
:   Parsed, not applied. A non-loopback bind of **serve** is governed by
    its own flags (**--tls-cert**, **--tls-key**,
    **--i-know-what-im-doing**).

**canary**
:   Parsed, not applied.

A dropped target is not probed and leaves no trace: there is no
per-target message and no audit event. When no target is left, **scan**
exits with "no targets after scope filter".

# SEE ALSO

*elsereno*(1), *elsereno.yaml*(5), *elsereno-security*(7).
