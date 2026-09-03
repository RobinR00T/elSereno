# ElSereno

```
   ______ _  _____
  |  ____| |/ ____|
  | |__  | | (___   ___ _ __ ___ _ __   ___
  |  __| | |\___ \ / _ \ '__/ _ \ '_ \ / _ \
  | |____| |____) |  __/ | |  __/ | | | (_) |
  |______|_|_____/ \___|_|  \___|_| |_|\___/
```

[![Release](https://img.shields.io/github/v/release/RobinR00T/elSereno?sort=semver&display_name=tag&color=2b6cb0)](https://github.com/RobinR00T/elSereno/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go version](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](go.mod)
[![CI](https://img.shields.io/github/actions/workflow/status/RobinR00T/elSereno/ci.yml?branch=main&label=ci)](https://github.com/RobinR00T/elSereno/actions/workflows/ci.yml)
[![Supply chain](https://img.shields.io/github/actions/workflow/status/RobinR00T/elSereno/supply-chain.yml?branch=main&label=supply-chain)](https://github.com/RobinR00T/elSereno/actions/workflows/supply-chain.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

> **Legal notice.** ElSereno is a tool for **authorised** security work. Do
> not run it against systems you do not own or are not explicitly
> authorised to test. Read [`LEGAL.md`](LEGAL.md) before first use. On
> first launch the binary records an acknowledgement of the acceptable-use
> policy.

ICS/OT and legacy-network exposure auditor. Combines multi-source ingestion
(Shodan, Censys, nmap XML, list, stdin), active fingerprinting, an
instrumentable proxy with per-protocol wire-layer write-ban, multi-factor
scoring, and a small web dashboard. An opt-in offensive module
(`-tags offensive`) adds writes, exploits, credential harvesting, and
individual dial gated by the [ADR-039](.context/decisions/039-offensive-architecture-triple-confirm.md)
triple-confirm wrapper. Linux and macOS; Windows is vNext.

Named after the *sereno*, the Spanish night watchman who carried a keyring
able to open every portal in the neighbourhood.

## Quick install (signed release)

Latest release: **[v1.15.0](https://github.com/RobinR00T/elSereno/releases/tag/v1.15.0)**
— Loose-end closure cycle: CWMP TransferComplete observer +
`elsereno discover --auto <CIDR>` + STIX 2.1 export sink +
audit cross-process flock + SIGHUP reload-style exit. See
[`.context/snapshots/v1.15.0-cwmp-discover-stix-flock-sighup.md`](.context/snapshots/v1.15.0-cwmp-discover-stix-flock-sighup.md)
for the per-chunk breakdown.

Previous release: [v1.14.0](https://github.com/RobinR00T/elSereno/releases/tag/v1.14.0)
— IPv6 cross-cutting (new `internal/netutil` package + target
canonicalisation across CLI parse boundaries + scope/dedupe
IPv6 contract pinned).

Previous release: [v1.13.0](https://github.com/RobinR00T/elSereno/releases/tag/v1.13.0)
— BACnet completion + CWMP polish (closes all 9 BACnet
mutating services with wire-level per-target-or-state
allowlists).

```sh
VERSION=1.15.0
OS=darwin       # or linux
ARCH=arm64      # or amd64
BASE="https://github.com/RobinR00T/elSereno/releases/download/v${VERSION}"

curl -fLO "${BASE}/elsereno_${VERSION}_${OS}_${ARCH}.tar.gz"
curl -fLO "${BASE}/checksums.txt"
curl -fLO "${BASE}/elsereno_${VERSION}_${OS}_${ARCH}.tar.gz.cyclonedx.json"

# SHA-256 integrity check
shasum -a 256 -c checksums.txt --ignore-missing

tar xzf "elsereno_${VERSION}_${OS}_${ARCH}.tar.gz"

# Two binaries bundled: elsereno (read-only) + elsereno-offensive
./elsereno_${VERSION}_${OS}_${ARCH}/elsereno version
./elsereno_${VERSION}_${OS}_${ARCH}/elsereno plugins list | wc -l   # 30
```

**Verify the GPG-signed tag** (canonical provenance for v1.8+):

```sh
# Import the maintainer key (ACE3B86BACACE7D6, Daniel Solís Agea)
curl -fL https://github.com/RobinR00T.gpg | gpg --import

# Clone + verify
git clone https://github.com/RobinR00T/elSereno.git && cd elSereno
git tag -v v1.15.0
# → "Good signature from Daniel Solís Agea <daniel.solis@zynap.com>"
```

**Supply-chain note**: v1.8.0 is the first **free-tier** release,
built locally with goreleaser + uploaded via `gh release upload`
(no GitHub Actions minutes consumed). Verification is GPG-signed
tag + SHA-256 + CycloneDX SBOMs. Releases v1.0.0 and v1.0.1 were
built via CI with the full cosign keyless + SLSA v1.0 provenance
+ GHCR docker image package; those artefacts are still available
on their respective release pages for operators who prefer that
chain. Detail in [RELEASING.md](RELEASING.md).

## Quickstart

> **Para usuarios nuevos**, empieza por una de estas rutas:
>
> | Necesitas… | Lee |
> |---|---|
> | Una guía completa: instalación + cada comando + ejemplos + workflows + troubleshooting | [`docs/MANUAL.md`](docs/MANUAL.md) |
> | Sólo instalar el binario en producción | [`INSTALL.md`](INSTALL.md) |
> | Clonar el repo y desarrollar | [`docs/DEV-SETUP.md`](docs/DEV-SETUP.md) |
> | Mandar findings a Splunk / Elastic / Loki / Prometheus | [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) |
> | Entender el modelo de seguridad / threat model | [`docs/SECURITY.md`](docs/SECURITY.md) |
> | Resolver una duda concreta | [`docs/FAQ.md`](docs/FAQ.md) |

### From source (dev workflow)

**One-shot path** (recommended — installs deps + builds + brings up
DB + vault + serve in two commands):

```sh
scripts/bootstrap.sh   # first time only; checks + prompts to install missing deps
scripts/start.sh       # every time you want to work: Docker + DB + build + serve
```

Full details — including all flags, env overrides, exit codes,
the vault model, and a common-failures table — in
[`docs/DEV-SETUP.md`](docs/DEV-SETUP.md).

**Manual path** (if you prefer to control every step):

```sh
docker compose -f docker-compose.dev.yml up -d
make build
./bin/elsereno doctor
./bin/elsereno vault init
./bin/elsereno vault unlock
./bin/elsereno serve                    # dashboard at http://127.0.0.1:8787
```

Non-interactive vault unlock (CI / preview runners):

```sh
umask 077 && printf '%s' "$PASSPHRASE" > ~/.elsereno/dev.pp && chmod 0600 ~/.elsereno/dev.pp
./bin/elsereno vault init   --vault-passphrase-file ~/.elsereno/dev.pp
./bin/elsereno serve        --vault-passphrase-file ~/.elsereno/dev.pp
```

See [ADR-026](.context/decisions/026-env-vars-with-secrets.md) for the secret-
transport policy behind the `--vault-passphrase-file` flag.

## Supported protocols

The default build registers **30 fingerprint plugins** (run
`elsereno plugins list` for the authoritative list on your binary).
Writes, exploits, credential harvest, dial, and the **write-gated
proxies** (24 protocols) ship behind `-tags offensive` with the
ADR-039 triple-confirm wrapper. Each gate scopes traffic at
multiple granularities: see the per-protocol details below. The
legacy-ICS write-gates (finsudp, slmp, gesrtp, codesys, redlion)
landed 2026-08/09 on validated public dissectors, each with an
end-to-end simulator demo under `scripts/demo-*-proxy.sh`.

| Protocol        | Port(s)            | Status (default build) |
|-----------------|--------------------|------------------------|
| **Modbus/TCP**  | 502                | probe + write-ban proxy · gated-write per-(unit, FC, address-range) plus per-FC 8-sub-function diagnostics gate (Force Listen Only / Clear Counters default-deny); structured `writes:` / `diag_subfunctions:` YAML round-trip (v1.2/v1.12) |
| S7comm          | 102                | probe + pass-through proxy |
| EtherNet/IP     | 44818              | probe + pass-through proxy |
| **BACnet/IP**   | 47808/udp          | Who-Is probe · gated-write per-service-choice + per-WriteProperty `(ObjectType, Instance, PropertyID)` via ASN.1 BER (v1.4/v1.12) |
| DNP3            | 20000              | probe + pass-through proxy |
| IEC 60870-5-104 | 2404               | TESTFR probe |
| HART-IP         | 5094               | session-initiate probe |
| Niagara Fox     | 1911, 4911         | banner probe |
| ATG Veeder-Root | 10001              | I20100 probe |
| **OPC UA**      | 4840               | Hello probe · gated-write service-TypeID + per-NodeId (numeric + String/GUID/ByteString) + per-CallMethod `(ObjectId, MethodId)` (v1.2/v1.6/v1.12) |
| XOT (X.25 / TCP) | 1998              | probe + pass-through proxy |
| AT modem (Hayes/GSM/EN 81-28) | 23, 7, 2001-2032, 3001, 4001-4009, 9999, 10001-10004 | probe + write-ban proxy |
| **SIP**         | 5060/udp+tcp       | OPTIONS probe · 15 PBX vendors · gated-proxy per-method + INVITE prefix + REGISTER AOR + From-domain (v1.4/v1.9/v1.10/v1.12) |
| **IAX2**        | 4569/udp           | NEW probe · RFC 5456 full-frame parser · gated-proxy per-subclass (v1.4) |
| **pbxhttp**     | 443, 80, 8088, 5001, 8443, 411 | HTTP admin-UI · 15 PBX brands · gated-proxy per-(method, path) (v1.4) |
| **CWMP / TR-069** | 7547             | ACS Inform probe · 15 ACS vendors · gated-proxy per-SOAP-RPC + per-parameter-path + per-firmware-URL (Download) (v1.11/v1.12) |
| **FINS**        | 9600/udp           | probe · gated UDP proxy per-(MRC, SRC) command + optional per-memory-area (Omron) |
| **SLMP**        | 5007               | probe · gated proxy per-command-code + optional per-device-code (MELSEC) |
| **GE-SRTP**     | 18245              | probe · gated proxy per-service-request code (GE/Emerson PACSystems) |
| **CoDeSys v3**  | 1217, 11740        | probe · gated stream proxy per-(L7 service, cmd), fail-closed magic scan |
| **Red Lion CR3** | 789               | probe · gated proxy per-Type opcode (Crimson v3 HMIs) |
| **OPC UA HTTPS** | 4843              | GetEndpoints POST · enumerates EndpointDescription list + security posture (a SecurityMode=None endpoint scores as higher exposure) |
| banner/dictionary | many             | Moxa/Lantronix/Digi/NetBurner/KONE/Otis/Schindler/OpenSSH |

The rows in **bold** carry write-gate proxies (this table is a
representative selection; 24 protocols have write-gates in total,
and more probe-only plugins ship than are listed here). The PBX
trio (SIP/IAX2/pbxhttp) landed in v1.3, CWMP in v1.4 (probe) +
v1.11 (gate); the legacy-ICS gates (FINS/SLMP/GE-SRTP/CoDeSys/Red
Lion) landed 2026-08/09. Run `elsereno plugins list` for the
authoritative list on your binary.

**Single-target live fingerprint**: `elsereno fingerprint probe
--plugin <name> --target host:port [--json]` runs one plugin's
live probe against one host:port (contrast `scan`, a banner sweep,
and `fingerprint validate`, which classifies captured bytes
offline).

**Attack-surface inputs** (7 providers, paginated since v1.12):
Shodan, Censys, FOFA, ZoomEye, ONYPHE, BinaryEdge need API keys;
Shodan InternetDB is **no-key** for low-volume IP lookups. Usage:

```sh
elsereno scan --input fofa:'protocol="iax2"' \
    --api-creds-file ~/.elsereno/api-creds.yaml

# No-key lookup-by-IP (rate-limited upstream to ~10 rps):
elsereno scan --input internetdb:8.8.8.8
```

Credentials live in a single YAML (0600 enforced at load) with
a per-provider block. Other accepted `--input` prefixes:
`shodan:<q>`, `censys:<q>`, `zoomeye:<q>`, `onyphe:<q>`,
`binaryedge:<q>`, `internetdb:<ip>` + the file-based `list:`,
`nmap:`, `stdin`.

See `.context/protocols/` for per-protocol notes and
`.context/STATE.md` for the authoritative live state.

## Target acquisition

### Shodan

- Create an account and an API key.
- Install the CLI: `pip install shodan`.
- **Store the key without leaking it** (avoid `ps` and shell history; see
  PITF-016 and PITF-032):

  ```sh
  read -rs KEY
  printf '%s' "$KEY" > ~/.shodan/api_key
  chmod 600 ~/.shodan/api_key
  unset KEY
  ```

- Alternative: environment variable `SHODAN_API_KEY`. Note: env vars are
  visible via `ps e` and `/proc/<pid>/environ` (PITF-032); prefer a 0600
  file for persistent use.
- **Never** run `shodan init <KEY>` with the key as an argument — it leaks
  to shell history and to `ps`.
- InternetDB (free): `curl -s https://internetdb.shodan.io/1.2.3.4 | jq`.

**Queries by protocol**:

| Protocol | Query |
|----------|-------|
| Modbus | `port:502` |
| S7comm | `port:102 "Basic Hardware"` |
| EtherNet/IP | `port:44818` |
| DNP3 | `port:20000 source address` |
| IEC-104 | `port:2404 asdu` |
| BACnet | `port:47808` |
| Niagara Fox | `port:1911,4911 "fox a 0"` |
| HART-IP | `port:5094` |
| ATG Veeder-Root | `port:10001 "I20100"` |
| XOT (X.25) | `port:1998` |
| Moxa NPort | `"Moxa NPort"` |
| Lantronix | `"Lantronix" port:9999` |
| Digi | `"Digi Connect" OR "PortServer"` |
| AT modem GSM | `"+CME ERROR"` |
| AT modem Hayes | `"OK" port:9999,2001,2002,23 "AT"` |

Download:

```sh
shodan search --limit 1000 --fields ip_str,port 'port:502' > modbus.txt
shodan download modbus-raw 'port:502'
shodan parse --fields ip_str,port --format csv modbus-raw.json.gz > modbus.csv
```

API with a 0600 key file:

```sh
curl --get "https://api.shodan.io/shodan/host/search" \
  --data-urlencode "key=$(cat ~/.shodan/api_key)" \
  --data-urlencode "query=port:502" --data-urlencode "limit=100" \
  | jq -r '.matches[] | [.ip_str, .port] | @csv' > modbus.csv
```

### Censys

```sh
pip install censys
censys config          # interactive; never via argv
censys search "services.port: 502" --pages 10 -o modbus.json
```

API v2 (credentials in env; mind `ps e`):

```sh
curl -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  "https://search.censys.io/api/v2/hosts/search?q=services.port:502&per_page=100" \
  | jq -r '.result.hits[] | [.ip, .services[0].port] | @csv' > modbus.csv
```

### nmap

```sh
# Privileged (requires CAP_NET_RAW or root):
nmap -sS -Pn -p 102,502,1911,1998,2404,4840,9999,10001,20000,44818,47808,5094 \
  -oX targets.xml -- <range>

# Unprivileged (connect scan):
nmap -sT -Pn -p 102,502,... -oX targets.xml -- <range>

# NSE:
nmap --script modbus-discover -p 502 -oX modbus.xml -- <range>
nmap --script s7-info -p 102 -oX s7.xml -- <range>
nmap --script bacnet-info -p 47808 -oX bacnet.xml -- <range>

# Serial / AT modems:
nmap -sT -Pn -p 23,7,2001-2032,3001,4001-4009,9999,10001-10004 -oX serial.xml -- <range>
```

The `--` before the range is important. ElSereno applies the same pattern
internally via `internal/exec.SafeCommand` with a typed `CommandSpec`
(ADR-024).

### Feeding ElSereno

```sh
elsereno scan --input list:modbus.txt --protocols modbus
elsereno scan --input nmap:targets.xml
elsereno scan --input shodan --query "port:502" --limit 500 --protocols modbus
elsereno scan --input censys --query "services.port: 502" --limit 500
cat ips.txt | elsereno scan --input stdin --protocols xot,atmodem,modbus
```

### API keys — prefer the vault

```sh
elsereno vault init
elsereno vault unlock
elsereno creds store shodan
elsereno creds store censys
```

Alternative env vars: `SHODAN_API_KEY`, `CENSYS_API_ID`,
`CENSYS_API_SECRET`. A warning is emitted when a TTY is detected and any
of these are set (ADR-026, PITF-032).

## Further reading

**Para usuarios y operadores:**

- [`docs/MANUAL.md`](docs/MANUAL.md) — manual completo end-to-end (CLI + dashboard + workflows + 22 secciones).
- [`docs/FAQ.md`](docs/FAQ.md) — preguntas frecuentes.
- [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) — recetas SIEM/observability.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — runbooks operacionales (release, Dependabot, post-public-flip, troubleshooting CI, handoff).
- [`docs/SECURITY.md`](docs/SECURITY.md) — modelo de seguridad + hardening checklist.
- [`INSTALL.md`](INSTALL.md) — todos los métodos de instalación con verificación SBOM.
- [`docs/manual/elsereno-manual.md`](docs/manual/elsereno-manual.md) — manual narrativo histórico de casos de uso.
- [`docs/manual/cheatsheet.txt`](docs/manual/cheatsheet.txt) — cheatsheet de comandos.
- [`docs/protocols/`](docs/protocols/) — engineering notes por protocolo.

**Para desarrolladores y contribuidores:**

- [`docs/DEV-SETUP.md`](docs/DEV-SETUP.md) — clonar repo + bootstrap + dev workflow.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — diseño interno.
- [`docs/openapi.yaml`](docs/openapi.yaml) — spec de la HTTP API.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — cómo contribuir.
- [`.github/SETTINGS.md`](.github/SETTINGS.md) — config esperada de GitHub repo (Code Scanning ON, approval policy, workflow permissions).

**Compliance y legal:**

- [`SECURITY.md`](SECURITY.md) — política de disclosure.
- [`LEGAL.md`](LEGAL.md) — uso aceptable.
- [`NON-GOALS.md`](NON-GOALS.md) — qué NO hace ElSereno (intencional).

## License

MIT — see [`LICENSE`](LICENSE).
