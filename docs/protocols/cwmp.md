# CWMP / TR-069 (ACS-CPE)

**Default port**: 7547/tcp (HTTP).
**Status**: probe (15 ACS vendor fingerprints) + write-gated
proxy (v1.11+).
**Offensive build**: per-SOAP-RPC + per-parameter-path +
per-firmware-URL allowlists.

## Probe

CPE-side probe: emits a synthetic `Inform` (TR-069 §3.2.1 events
0 BOOTSTRAP / 1 BOOT / 2 PERIODIC) and classifies the ACS
response. Vendor fingerprint covers 15 ACS implementations
(GenieACS, ACS-Lite, FreeACS, OpenACS, Calix Cloud, Adtran Mosaic,
Nokia AMS, Ericsson HDM, Huawei IMS, ZTE NetNumen, Cisco PSM,
Affirmed, Incognito Auto Configuration, Axiros, Friendly tech).

## Default-build refusal posture

The default proxy refuses every client byte with
`HTTP/1.1 403 Forbidden`. The write-gated variant (offensive
build) replaces that.

## Offensive write-gate

The gate parses each POST's SOAP envelope to extract the first
RPC name under `<*:Body>`, then applies three layers (each
opt-in):

| Layer | Flag | Applies to | Match | Since |
|-------|------|------------|-------|-------|
| RPC | `--rpc Reboot` | every gated POST | exact, case-sensitive per TR-069 §A.4 | v1.11 |
| Parameter path | `--param-prefix InternetGatewayDevice.WANDevice.` | `SetParameterValues` / `SetParameterAttributes` | every `<Name>` in body must match at least one prefix | v1.12 |
| Firmware URL | `--firmware url=…;sha256=…` | `Download` only | exact URL match (case-folded scheme+host, default-port stripped) | v1.12 |

**Always-safe RPCs** (pass without allowlist): `GetRPCMethods`,
`GetParameter{Names,Values,Attributes}` + their `Response`
variants, `Inform` / `InformResponse`, `TransferComplete` /
`TransferCompleteResponse`, `AutonomousTransferComplete`,
`Kicked` / `KickedResponse`, `Fault`. Blocking these would break
CPE registration.

**Refusals** are HTTP 200 OK + a TR-069 SOAP fault body. Three
distinct fault codes per refusal class:

- `9001 Request denied` — RPC name not in `--rpc` allowlist.
- `9005 Invalid parameter name` — at least one `<Name>` outside
  the `--param-prefix` allowlist.
- `9001 Request denied` + `X-Elsereno-Gate-Reason: CWMP firmware
  URL not in session allowlist` — `Download` URL not in
  `--firmware` list.

## SHA-256 metadata note

TR-069's `Download` RPC does NOT carry the firmware checksum;
the CPE downloads the file AFTER the RPC and reports the actual
hash later via `TransferComplete`. The gate enforces URL only.
The optional `sha256=` field in `--firmware` is metadata —
written to the YAML and the dry-run output for downstream
verification (e.g. on a syslog of the `TransferComplete` reply).

### Pre-flight verifier (v1.13+)

Operators can verify the URL contents BEFORE opening the change
window using:

```sh
elsereno-offensive write cwmp verify-firmware \
  --allow-file /etc/elsereno/cwmp-gate.yaml
```

The command side-fetches each `firmware:` entry's URL via
HTTPS, computes SHA-256 over the response body, and compares
against the operator-supplied hash. Output is one line per URL
with `✓ MATCH` / `✗ MISMATCH` / `! ERROR` / `- SKIPPED` (when
no `sha256:` field). Exit code: `0` all match, `1` any
mismatch, `2` usage / fetch error.

Use this to catch a hostile / misconfigured ACS that swapped
the firmware image at the URL between the dry-run when the
operator computed the hash and the actual change window. The
gate alone can't see the body content — it only enforces URL
match at RPC time.

## Operator example

```sh
elsereno-offensive write cwmp dry-run \
  --target acs.example.com:7547 \
  --rpc SetParameterValues --rpc Reboot --rpc Download \
  --param-prefix "InternetGatewayDevice.WANDevice." \
  --param-prefix "InternetGatewayDevice.LANDevice." \
  --firmware "url=https://acs.example.com/fw/router-1.2.3.bin;sha256=abc123…" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/cwmp-gate.yaml
```

YAML keys: `rpcs:`, `param_prefixes:`, `firmware:` (with
`{url, sha256}` entries).

## See also

- `.context/protocols/cwmp.md` and the v1.11 / v1.12 snapshots.
- TR-069 Annex A fault-code catalogue.
