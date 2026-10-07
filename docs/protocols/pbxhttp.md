# PBX HTTP admin-UI

**Default port**: 443 (HTTPS). PBX admin UIs also listen on 80,
8088, 5001, 8443; the plugin speaks HTTPS only (no plain-HTTP
fallback) and `scan` runs it on 443, so use `fingerprint probe` for
another HTTPS port.
**Status**: probe + write-gated proxy.
**Offensive build**: per-(method, path) allowlist.

## Probe

One HTTPS `GET /`; the response headers and body are matched against
the 14-vendor dictionary in `pbxhttp/vendor.go`: FreePBX, PBXact,
3CX, Yeastar, Cisco UCM, Avaya, Mitel, Grandstream, Fanvil, Yealink,
Asterisk (HTTP Manager), Switchvox, Elastix and FreeSWITCH. The TLS
certificate is not inspected.

## Default-build refusal posture

The default proxy is deny-all: every client gets `HTTP/1.1 403
Forbidden` and nothing is forwarded. The method/path gate (`405 Method
Not Allowed` for unsafe methods) is the offensive build's
(`offensive/write/pbxhttp`).

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
