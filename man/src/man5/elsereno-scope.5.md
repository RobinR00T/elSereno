% ELSERENO-SCOPE(5) ElSereno scope file | File formats
% ElSereno project
% 2026-04-19

# NAME

**scope.yaml** — authorised scope file for *elsereno*(1)

# DESCRIPTION

A *scope.yaml* file defines the authorised ranges, ports, protocols, web
binds, dialling blacklist, and optional canary for an engagement.

A scope file is **optional** — when absent, ElSereno requires an explicit
acceptable-use acknowledgement at every active command.

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
  blocked_numbers:
    - "+34112"
    - "+34062"
canary:
  enabled: false
  alert_webhook: ""
```

# SEMANTICS

**ranges**
:   CIDRs. Both IPv4 and IPv6 are supported.

**ports.allow / ports.deny**
:   Deny wins over allow. If **allow** is empty, all ports are allowed
    subject to **deny**.

**protocols.allow / protocols.deny**
:   Same precedence as ports.

**binds.allow**
:   Addresses the web server is allowed to bind to. Non-loopback binds
    additionally require **--tls-cert**, **--tls-key**, and
    **--i-know-what-im-doing**.

**dial.blocked_numbers**
:   Additional numbers blocked on offensive dialling. ≤3-digit numbers are
    always blocked regardless.

**canary**
:   Optional webhook that fires when the canary condition is met (to be
    defined per engagement).

# SEE ALSO

*elsereno*(1), *elsereno.yaml*(5), *elsereno-security*(7).
