# ElSereno

```
   ______ _  _____
  |  ____| |/ ____|
  | |__  | | (___   ___ _ __ ___ _ __   ___
  |  __| | |\___ \ / _ \ '__/ _ \ '_ \ / _ \
  | |____| |____) |  __/ | |  __/ | | | (_) |
  |______|_|_____/ \___|_|  \___|_| |_|\___/
```

> **Legal notice.** ElSereno is a tool for **authorised** security work. Do
> not run it against systems you do not own or are not explicitly
> authorised to test. Read `LEGAL.md` before first use. On first launch the
> binary records an acknowledgement of the acceptable-use policy.

ICS/OT and legacy-network exposure auditor. Combines multi-source ingestion
(Shodan, Censys, nmap XML, list, stdin), active fingerprinting, a REPL, an
instrumentable proxy, multi-factor scoring, and a small web + TUI dashboard.
An opt-in offensive module (`-tags offensive`) adds writes, exploits,
credential harvesting, and individual dial. Linux and macOS; Windows is
vNext.

Named after the *sereno*, the Spanish night watchman who carried a keyring
able to open every portal in the neighbourhood.

## Quickstart

```sh
go install local/elsereno/cmd/elsereno@latest
docker compose -f docker-compose.dev.yml up -d
elsereno init
elsereno doctor
elsereno vault init
elsereno vault unlock
elsereno serve
```

## Supported protocols

| Protocol      | Port(s)            | Status (F0) |
|---------------|--------------------|-------------|
| Modbus/TCP    | 502                | planned     |
| S7comm        | 102                | planned     |
| EtherNet/IP   | 44818              | planned     |
| BACnet/IP     | 47808              | planned     |
| DNP3          | 20000              | planned     |
| IEC 60870-5-104 | 2404             | planned     |
| HART-IP       | 5094               | planned     |
| Niagara Fox   | 1911, 4911         | planned     |
| ATG Veeder-Root | 10001            | planned     |
| XOT (X.25 over TCP) | 1998         | planned     |
| AT modem (Hayes/GSM/EN 81-28) | 23, 7, 2001-2032, 3001, 4001-4009, 9999, 10001-10004 | planned |
| banner/dictionary | many           | planned     |

See `.context/protocols/` for per-protocol notes as they are added.

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
