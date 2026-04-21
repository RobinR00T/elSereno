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

```sh
# Pick your platform; darwin/linux × amd64/arm64 available.
VERSION=1.0.0
OS=darwin       # or linux
ARCH=arm64      # or amd64
URL="https://github.com/RobinR00T/elSereno/releases/download/v${VERSION}/elsereno_${VERSION}_${OS}_${ARCH}.tar.gz"

curl -fL -o "elsereno_${VERSION}.tar.gz" "$URL"
curl -fL -o checksums.txt  "https://github.com/RobinR00T/elSereno/releases/download/v${VERSION}/checksums.txt"

# Integrity check (abort if mismatch).
shasum -a 256 -c checksums.txt --ignore-missing

tar xzf "elsereno_${VERSION}.tar.gz"
./elsereno version
```

Optional keyless-signature verification (requires
[cosign](https://github.com/sigstore/cosign)):

```sh
curl -fL -o checksums.txt.sig \
  "https://github.com/RobinR00T/elSereno/releases/download/v${VERSION}/checksums.txt.sig"
# Bundle-mode verification ships in v1.1; for v1.0.0 the signature is
# recorded in Sigstore's Rekor transparency log.
```

## Quickstart

### Via pre-built OCI image (v1.1+)

```sh
# Latest release (multi-arch: linux/amd64 + linux/arm64)
docker pull ghcr.io/robinr00t/elsereno:latest
docker run --rm -p 8787:8787 \
  -v "$HOME/.elsereno:/home/nonroot/.elsereno" \
  ghcr.io/robinr00t/elsereno:latest serve --addr 0.0.0.0:8787
```

The manifest is cosign-signed (keyless Sigstore) and carries a
CycloneDX SBOM + SLSA-compatible provenance attestation. Verify end-
to-end with:

```sh
cosign verify ghcr.io/robinr00t/elsereno:v1.1.0 \
  --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com'

cosign download sbom ghcr.io/robinr00t/elsereno:v1.1.0
```

### From source (dev workflow)

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

See [ADR-026](.context/decisions/026-secret-transport.md) for the secret-
transport policy behind the `--vault-passphrase-file` flag.

## Supported protocols

As of F5 (2026-04-19) the default build registers 12 plugins. Writes,
exploits, credential harvest, and dial ship behind `-tags offensive`
with the ADR-039 triple-confirm wrapper.

| Protocol      | Port(s)            | Status      |
|---------------|--------------------|-------------|
| Modbus/TCP    | 502                | implemented (read-only proxy write-ban) |
| S7comm        | 102                | implemented (probe + pass-through proxy) |
| EtherNet/IP   | 44818              | implemented (probe + pass-through proxy) |
| BACnet/IP     | 47808/udp          | implemented (Who-Is probe)              |
| DNP3          | 20000              | implemented (probe + pass-through proxy) |
| IEC 60870-5-104 | 2404             | implemented (TESTFR probe)              |
| HART-IP       | 5094               | implemented (session-initiate probe)    |
| Niagara Fox   | 1911, 4911         | implemented (banner probe)              |
| ATG Veeder-Root | 10001            | implemented (I20100 probe)              |
| XOT (X.25 over TCP) | 1998         | implemented (probe + pass-through proxy) |
| AT modem (Hayes/GSM/EN 81-28) | 23, 7, 2001-2032, 3001, 4001-4009, 9999, 10001-10004 | implemented (probe + write-ban proxy) |
| banner/dictionary | many           | implemented (Moxa/Lantronix/Digi/NetBurner/KONE/Otis/Schindler/OpenSSH) |

See `.context/protocols/` for per-protocol notes and `.context/STATE.md` for
the authoritative live state.

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

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`SECURITY.md`](SECURITY.md)
- [`LEGAL.md`](LEGAL.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`NON-GOALS.md`](NON-GOALS.md)

## License

MIT — see [`LICENSE`](LICENSE).
