% ELSERENO(1) ElSereno user commands | Commands
% ElSereno project
% 2026-04-26

# NAME

**elsereno**: ICS/OT and legacy-network exposure auditor

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
    triple-confirm wrapper (ADR-039), `--accept-writes`,
    `--confirm-target`, `--confirm-token`.

# COMMANDS

The default-build subcommand list is below. Run
`elsereno *command* --help` for per-command flags.

**api**
:   HTTP API meta-operations. `api openapi` prints the live
    OpenAPI 3.1 spec.

**audit**
:   Audit-chain operations on `~/.elsereno/audit.jsonl`:
    **verify-file** walks the chain, **export** writes events for a
    SIEM (ndjson, cef, syslog), **serve** runs the fan-in daemon on a
    Unix socket. **verify**, **purge** and **compact** check their flags
    and then do nothing yet (exit 69).

**backup**
:   Encrypted backup + restore (vault-keyed AES-256-GCM).

**completion**
:   Generate shell completions (placeholder; see
    `--help` until cobra's generator is wired).

**config**
:   Inspect and validate configuration: **show**, **lint**. (Canonical
    formatting is the top-level **fmt**.)

**creds**
:   Manage stored credentials inside the vault.

**db**
:   Database operations: **migrate up/down**, **status**,
    **verify**.

**doctor**
:   Run six local preflight checks: Go runtime, platform, raw-socket
    privilege, nmap on PATH, IPv6, free disk. Neither root nor nmap is
    needed to scan; reads no config, vault or database.

**explain**
:   Explain how a finding's score was computed (ADR-006 factors).

**fingerprint**
:   Debug one plugin: **probe** a live host:port, **capture** one TCP
    connection's bytes to a file, **validate** a plugin against
    captured bytes (offline).

**fmt**
:   Re-emit a YAML config with canonical formatting.

**goose**
:   IEC 61850 GOOSE/SV dissector, offline: **decode** one frame,
    **monitor** a frame stream for spoofing signs; **monitor --iface**
    reads a receive-only AF_PACKET socket on Linux (CAP_NET_RAW).

**gen-man**
:   Generate man1 pages via cobra/doc (placeholder; current man1
    lives under `man/src/man1/*.md`).

**legal**
:   Print the acceptable-use policy disclaimer.

**lint**
:   Validate **elsereno.yaml** and optional **scope.yaml**.

**modbus**
:   **modbus monitor --file**: passive, offline; reports the writes and
    mutating diagnostics in a Modbus/TCP frame stream (one hex frame per
    line).

**opcua**
:   Read-only OPC UA recon: **probe-anon** confirms an anonymous session
    opens; **probe-write** walks the address space as that user and
    flags writeable tags.

**plaintext-check**
:   Tests whether a reachable service negotiates TLS; one that does not
    is flagged as cleartext.

**plugins**
:   Manage protocol plugins. **plugins list** prints the
    compiled-in set (35 in the default build).

**discover**
:   `discover --auto <CIDR>` runs a TCP-connect sweep across
    the CIDR + the well-known port of every registered plugin.
    Pipe-friendly: `--format list` emits `host:port` lines for
    `scan --input list:-` (`list:-` reads stdin).

**profinet**
:   PROFINET DCP codec, offline: **decode** a frame, **encode-identify**
    prints an Identify-All request.

**proxy**
:   Protocol-aware interception proxy. **proxy listen** runs a
    write-gated proxy in the offensive build. In the default build
    **proxy** is a stub that exits 75 (planned): the per-plugin
    handlers that refuse writes (write-ban, deny-all, fail-closed)
    exist as library code, but no command serves them yet.

**scan**
:   Scan a set of targets and emit findings.
    `--input <provider>:<query>` accepts `list:`, `nmap:`,
    `stdin`, `shodan:`, `censys:`, `fofa:`, `zoomeye:`,
    `onyphe:`, `binaryedge:`, `internetdb:`. **shodan**, **censys**,
    **fofa**, **zoomeye**, **onyphe** and **binaryedge** need
    `--api-creds-file <0600.yaml>`;
    **internetdb** needs no key and takes an IP, `file:<path>` or `-`
    (no CIDR).
    Each target goes to every plugin whose default port it is on
    (**banner** probes every target; opt-in plugins run only when
    named, and then probe every listed target, having no default
    port); `--plugin <name>[,<name>]` restricts the set. Each
    finding carries the target's address and port.
    `--output-format` accepts `ndjson`, `csv` and `stix` (STIX 2.1
    bundle for MISP / OpenCTI / ThreatBus, v1.15+); `--output
    <file>` writes to a file instead of stdout. To probe one
    plugin on another port, use **fingerprint probe**.

**s7**
:   Read-only S7comm recon of a Siemens CPU: **probe-identity** (model,
    firmware), **probe-protection** (protection level), **probe** (both).

**schedule**
:   Manage scheduled scans through a running **serve** (**list**,
    **get**, **enable**, **disable**, **delete**, **clone**, **import**,
    **export**, **pause-all**, **resume-all**, **stats**).

**scoring**
:   Inspect the scoring weights and severity thresholds.

**serve**
:   Start the HTTP dashboard at the configured listen address +
    serve `/api/v1`. With **--scan-store** memory or db, scans queued
    from the dashboard, the API or a schedule run against their
    targets (limited by **--scope** when given); jobs already queued
    when serve starts do not run. Findings go to the SSE stream and,
    with **DATABASE_URL**, to the runs and findings tables.

**standards**
:   Prints the mapping from plugins to the security-standard
    weaknesses their findings evidence (NIST SP 800-82 Rev. 4).

**triage**
:   Group NDJSON findings into quick-win / strategic / routine.

**tui**
:   Interactive terminal UI: empty panes, **--input** (scan from the
    TUI), **--replay** a recorded NDJSON, **--feed -** from stdin, or
    **--watch** a remote SSE stream.

**vault**
:   Manage the encrypted credential vault: **init**, **unlock**,
    **lock**, **status**.

**version**
:   Print binary version, commit, and build date.

**why**
:   Explain the scoring posture for a target.

**diff**, **init**, **repl**, **token**
:   Planned: each exits 75 with a notice on stderr.

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

Seven of the 18 write-gated proxies accept the `--allow-file
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
:   Simulate side effects without performing them. Only **schedule
    delete**, **enable**, **disable**, **clone**, **import**,
    **pause-all** and **resume-all** implement it; every other command
    refuses to run with it (exit 64) instead of acting.

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

`./elsereno.yaml`
:   Per-project config, last in the lookup order (see *elsereno.yaml*(5)).
    A *scope.yaml* is read only when passed with **--scope**, which every
    command that connects to a target accepts (*elsereno-scope*(5)).

# EXIT CODES

`0`
:   success.

`1`
:   error (also an unknown flag or a missing argument).

`64`
:   usage error, *EX_USAGE* (also a name given as **--target** to a
    write-class verb with **--scope**).

`66`
:   nothing left to do, *EX_NOINPUT* (no targets after the scope filter).

`68`
:   a **--target** name that does not resolve, *EX_NOHOST*: with
    **--scope**, and always in **fingerprint probe**.

`77`
:   refused by **--scope**, *EX_NOPERM*: a target outside its ranges or
    ports, or a plugin outside its protocols.

`78`
:   configuration error, *EX_CONFIG*: a config or scope file that does
    not parse.

`128 + signum`
:   killed by a signal (e.g. SIGINT → **130**, SIGTERM → **143**).

`75`
:   *EX_TEMPFAIL*: emitted by the verbs that are still stubs
    (planned for a later phase, **proxy** in the default build
    among them) and by `proxy listen` (offensive build) on SIGHUP. Distinguishable from a real crash via
    systemd's `RestartPreventExitStatus=`; supervisor restarts
    with the new allowlist + freshly minted confirm-token
    (v1.15+).

# ENVIRONMENT

**ELSERENO_VAULT_PASSPHRASE**
:   Emits a warning when a TTY is present; prefer `vault unlock`
    or a 0600 file.

**NO_COLOR**, **COLORTERM**, **TERM**
:   The root help (**elsereno**, **elsereno --help**, **elsereno
    help**) starts with the elSereno ASCII logo when standard output
    is a terminal and **--quiet** is not set. It is in colour when
    **COLORTERM** is *truecolor* or *24bit*, **NO_COLOR** is unset and
    **TERM** is not *dumb*; otherwise plain ASCII. Off a terminal the
    help has no logo.

**DATABASE_URL**
:   Postgres DSN. Optional; missing → DB-backed panels degrade
    to "backend unavailable", dashboard scans keep their findings
    only on the live stream, and the rest of `serve` keeps
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
