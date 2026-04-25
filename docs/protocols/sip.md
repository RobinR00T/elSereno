# SIP (Session Initiation Protocol)

**Default ports**: 5060/udp + 5060/tcp.
**Status**: probe + write-gated proxy (default build refuses
mutating methods with `405 Method Not Allowed`).
**Offensive build (`-tags offensive`)**: per-method + per-INVITE-
prefix + per-REGISTER-AOR + per-From-domain allowlists.

## Probe

`OPTIONS sip:<host> SIP/2.0` issued via UDP first, falling back
to TCP. Parses the response banner / `Server:` header against
the vendor dictionary (15 PBX brands: Asterisk, FreeSWITCH,
Kamailio, OpenSIPS, 3CX, FreePBX, FusionPBX, Mitel, Avaya, Cisco
CME, Audiocodes, Patton, Ribbon, Sangoma, Yeastar).

## Default-build refusal posture

Every SIP request from the client is forwarded only when its
method is in the **always-safe** set (`OPTIONS`, `ACK`, `BYE`,
`CANCEL`, `PRACK`). Anything else (INVITE / REGISTER / MESSAGE /
SUBSCRIBE / NOTIFY / REFER / PUBLISH / UPDATE / INFO) returns:

    SIP/2.0 405 Method Not Allowed
    Allow: OPTIONS, ACK, BYE, CANCEL, PRACK
    X-Elsereno-Gate-Reason: …

## Offensive write-gate

Four allowlists, each opt-in. Empty list disables that layer.
Hash ladder degrades cleanly so v1.4–v1.11 confirm-tokens
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
--allow-file <path>` — the YAML carries `methods:`,
`to_prefixes:`, `aors:`, `from_domains:`.

## See also

- ADR-039 (triple-confirm) and ADR-040 (write-gate template) in
  `.context/decisions/`.
- `.context/protocols/sip.md` for engineering-level wire notes.
- v1.12.0 snapshot for the From-domain identity-spoof rationale.
