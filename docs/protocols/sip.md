# SIP (Session Initiation Protocol)

**Default ports**: 5060/udp + 5060/tcp.
**Status**: probe (UDP) + deny-all proxy in the default build
(`SIP/2.0 403 Forbidden` to every client); the write-gated proxy is
the offensive build's.
**Offensive build (`-tags offensive`)**: per-method + per-INVITE-
prefix + per-REGISTER-AOR + per-From-domain allowlists.

## Probe

`OPTIONS sip:<host:port> SIP/2.0` over **UDP only** (the plugin's
default transport; nothing in the default build switches it to TCP,
and there is no fallback). The `Server:` and `User-Agent:` headers are
matched against the vendor dictionary (`sip/vendor.go`, 15 brands):
Asterisk, FreePBX, 3CX, Cisco UCM, Cisco SIP gateway, Mitel, Avaya,
Yeastar, Grandstream, Fanvil, Yealink, Kamailio, OpenSIPS, FreeSWITCH
and SER. Any SIP status line in reply yields a scored finding.

## Default-build refusal posture

The default proxy is deny-all: it answers every client with
`SIP/2.0 403 Forbidden` and forwards nothing. The method-aware gate
(always-safe `OPTIONS` / `ACK` / `BYE` / `CANCEL` / `PRACK`, `405
Method Not Allowed` for the rest) is the offensive build's
(`offensive/write/sip`).

## Offensive write-gate

Four allowlists, each opt-in. Empty list disables that layer.
Hash ladder degrades cleanly so v1.4-v1.11 confirm-tokens
remain valid for operators who skip the new layers.

| Layer | Flag | Applies to | Match | Since |
|-------|------|------------|-------|-------|
| Method | `--method INVITE` | every gated request | exact, case-insensitive | v1.4 |
| INVITE destination | `--to-prefix +34` | INVITE only | URI user-part prefix, case-insensitive | v1.9 |
| REGISTER AOR | `--aor sip:alice@pbx` | REGISTER only | exact canonical user@host | v1.10 |
| From-domain | `--from-domain pbx.internal` | every gated method | exact host | v1.12 |

Refusals are SIP/2.0 403 Forbidden + `X-Elsereno-Gate-Reason`:
"INVITE destination not in To-URI prefix allowlist", "AOR not
in session allowlist (REGISTER hijack guard)", or "From domain
not in session allowlist (identity-spoof guard)".

## Operator example

```sh
elsereno-offensive write sip dry-run \
  --target pbx.internal:5060 \
  --method INVITE --method REGISTER \
  --to-prefix "+34" --to-prefix "+44" \
  --aor "sip:alice@pbx.internal" \
  --aor "sip:bob@pbx.internal" \
  --from-domain pbx.internal \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/sip-gate.yaml
```

The allow-file round-trips lossless through `proxy listen
--allow-file <path>`: the YAML carries `methods:`,
`to_prefixes:`, `aors:`, `from_domains:`.

## See also

- ADR-039 (triple-confirm) and ADR-040 (write-gate template) in
  `.context/decisions/`.
- `.context/protocols/sip.md` for engineering-level wire notes.
- v1.12.0 snapshot for the From-domain identity-spoof rationale.
