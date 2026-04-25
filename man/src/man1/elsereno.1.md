% ELSERENO(1) ElSereno user commands | Commands
% ElSereno project
% 2026-04-25

# NAME

**elsereno** — ICS/OT and legacy-network exposure auditor

# SYNOPSIS

| **elsereno** \[**\--config** *file*] \[**\--dry-run**] \[**\--format** *fmt*] *command* \[*args*]

# DESCRIPTION

**ElSereno** scans for and audits exposure of legacy + ICS / OT
network protocols (Modbus, S7, EtherNet/IP, BACnet, DNP3,
IEC 60870-5-104, HART-IP, Niagara Fox, OPC UA, ATG, XOT, AT
modems, banner / dictionary, plus PBX SIP / IAX2 / pbxhttp /
TR-069 CWMP). Two binaries ship from the same module:

**elsereno**
:   Default (read-only) build. Scan, fingerprint, score, triage,
    serve dashboard. Writes refused at the wire layer.

**elsereno-offensive**
:   `-tags offensive` build. Adds **dial**, **exploit**,
    **harvest**, **proxy listen** (write-gated), and **write**
    subcommands. Every mutating call clears the
    triple-confirm wrapper (ADR-039) — `--accept-writes`,
    `--confirm-target`, `--confirm-token`.

# COMMANDS

The default-build subcommand list is below. Run
`elsereno *command* --help` for per-command flags.

**api**
:   HTTP API meta-operations. `api openapi` prints the live
    OpenAPI 3.1 spec.

**audit**
:   Audit-log operations: **show**, **verify-file**, **import**,
    **rebase**, **purge**.

**backup**
:   Encrypted backup + restore (vault-keyed AES-256-GCM).

**completion**
:   Generate shell completions (placeholder; see
    `--help` until cobra's generator is wired).

**config**
:   Inspect and validate configuration. Subcommands include
    **show**, **lint**, **fmt**.

**creds**
:   Manage stored credentials inside the vault.

**db**
:   Database operations: **migrate up/down**, **status**,
    **verify**.

**doctor**
:   Run cross-platform preflight checks (Go runtime, capabilities,
    nmap, IPv6, DNS, disk).

**explain**
:   Explain how a finding's score was computed (ADR-006 factors).

**fmt**
:   Re-emit a YAML config with canonical formatting.

**gen-man**
:   Generate man1 pages via cobra/doc (placeholder; current man1
    lives under `man/src/man1/*.md`).

**legal**
:   Print the acceptable-use policy disclaimer.

**lint**
:   Validate **elsereno.yaml** and optional **scope.yaml**.

**plugins**
:   Manage protocol plugins. **plugins list** prints the
    compiled-in set (17 in the v1.12 default build).

**proxy**
:   Protocol-aware interception proxy. **proxy listen** runs a
    write-gated proxy in the offensive build (read-only fail-
    closed in default).

**scan**
:   Scan a set of targets and emit findings.
    `--input <provider>:<query>` accepts `list:`, `nmap:`,
    `stdin`, `shodan:`, `censys:`, `fofa:`, `zoomeye:`,
    `onyphe:`, `internetdb:`. The first 5 require
    `--api-creds-file <0600.yaml>`; **internetdb** is no-key.

**scoring**
:   Inspect the scoring weights and severity thresholds.

**serve**
:   Start the HTTP dashboard at the configured listen address +
    serve `/api/v1`.

**triage**
:   Group NDJSON findings into quick-win / strategic / routine.

**vault**
:   Manage the encrypted credential vault. **vault init**,
    **unlock**, **lock**.

**version**
:   Print binary version, commit, and build date.

**why**
:   Explain the scoring posture for a target.

# OFFENSIVE-ONLY COMMANDS

The `-tags offensive` build adds:

**dial**
:   Dial guard (ADR-041). Subcommands: **validate** (single
    number) and **batch** (wardialing batch with
    `--numbers-file`).

**exploit**
:   CVE exploit catalogue. **exploit list** + **exploit dry-run**
    + **exploit run**.

**harvest**
:   Credential harvest probes (telnet / ftp / http-basic / snmp).

**write**
:   Protocol-specific write operations. Per-protocol subcommands:
    **modbus dry-run**, **modbus send**, **modbus
    proxy-dry-run**, **sip dry-run**, **iax2 dry-run**,
    **pbxhttp dry-run**, **opcua dry-run**, **bacnet dry-run**,
    **cwmp dry-run**.

# WRITE-GATE FLAGS (offensive build)

The seven write-gated proxies all share the `--allow-file
<path.yaml>` round-trip flow. Direct CLI flags per proxy:

**Modbus**
:   `--function <FC>`, `--write unit=N;fc=M;start=A;end=B`.

**OPC UA**
:   `--service <TypeID>`,
    `--node-id ns=N;i=M|s=STR|g=HEX|b=HEX`,
    `--call-method object=…;method=…`.

**SIP**
:   `--method <NAME>`, `--to-prefix <prefix>`, `--aor <AOR>`,
    `--from-domain <host>`.

**IAX2**
:   `--subclass <NAME>`.

**pbxhttp**
:   `--allow METHOD:/path`.

**BACnet**
:   `--service-choice <N>`,
    `--object type=N;instance=M;property=P`.

**CWMP**
:   `--rpc <Name>`, `--param-prefix <prefix>`,
    `--firmware url=…;sha256=…`.

# GLOBAL FLAGS

**\--config** *file*
:   Path to `elsereno.yaml` (overrides default lookup order).

**\--dry-run**
:   Simulate side effects without performing them.

**\--format** *yaml|json|table|ndjson|csv*
:   Output format selector (per-command support varies).

**\--quiet** (offensive-build only)
:   Suppress non-critical output.

# FILES

`~/.elsereno/vault.v1.bin`
:   AES-GCM + Argon2id vault.

`~/.elsereno/audit.jsonl`
:   JCS+SHA-256 audit chain (0600).

`~/.elsereno/dev.pp`
:   Operator-supplied passphrase file (0600). Pass via
    `--vault-passphrase-file`.

`~/.elsereno/api-creds.yaml`
:   Provider API keys for `--input <provider>:<q>`. 0600
    enforced at load.

`./elsereno.yaml`, `./scope.yaml`
:   Per-project config + scope.

# EXIT CODES

`0`
:   success.

`1`
:   error.

`2`
:   usage error.

`128 + signum`
:   killed by a signal (e.g. SIGINT → **130**, SIGTERM → **143**).

# ENVIRONMENT

**ELSERENO_VAULT_PASSPHRASE**
:   Emits a warning when a TTY is present; prefer `vault unlock`
    or a 0600 file.

**DATABASE_URL**
:   Postgres DSN. Optional; missing → DB-backed panels degrade
    to "backend unavailable" and the rest of `serve` keeps
    running.

# SEE ALSO

*elsereno-protocols*(7), *elsereno-security*(7),
*elsereno.yaml*(5), *elsereno-scope*(5),
*elsereno-scoring*(5).

The `README.md`, `docs/manual/elsereno-manual.md`, and
`docs/manual/cheatsheet.txt` carry operator-facing recipes for
common workflows.

# COPYRIGHT

ElSereno project. See `LEGAL.md` and `LICENSE` in the source
distribution. Dual-use: do not run offensive subcommands without
written authorisation, scope approval, and an explicit
maintenance window.
