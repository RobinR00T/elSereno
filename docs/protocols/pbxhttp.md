# PBX HTTP admin-UI

**Default ports**: 443, 80, 8088, 5001, 8443, 411 (vendor mix).
**Status**: probe + write-gated proxy.
**Offensive build**: per-(method, path) allowlist.

## Probe

Performs a TLS-aware HTTP probe and matches the response banner
+ TLS leaf-cert subject + page title against the 15-vendor PBX
HTTP fingerprint dictionary (FreePBX, FusionPBX, 3CX, Asterisk
GUI, Issabel, Yeastar, Sangoma, Cisco UCM, Mitel, Avaya, Audiocodes,
Patton, Ribbon, Grandstream, Polycom).

## Default-build refusal posture

The default proxy is a strict HTTP reverse-proxy that:
- Forwards `GET` / `HEAD` / `OPTIONS` requests verbatim.
- Refuses any other method with `HTTP/1.1 405 Method Not Allowed`
  + `Allow: GET, HEAD, OPTIONS`.
- Refuses any path not in the allowlist (`HTTP/1.1 403 Forbidden`).

## Offensive write-gate

Per-(method, path) tuples. Operator allowlists the exact
admin-UI endpoints that the change window needs:

```sh
elsereno-offensive write pbxhttp dry-run \
  --target pbx.internal:443 \
  --allow "POST:/admin/config.php" \
  --allow "DELETE:/admin/user/42" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/pbxhttp-gate.yaml
```

YAML: `allow: [POST:/admin/config.php, DELETE:/admin/user/42]`.
Match is exact on path; method is case-insensitive.

## See also

- `.context/protocols/pbxhttp.md` for vendor fingerprint details.
