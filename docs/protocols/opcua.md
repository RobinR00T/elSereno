# OPC UA (binary)

**Default port**: 4840/tcp.
**Status**: probe + write-gated proxy.
**Offensive build**: service-TypeID + per-NodeId (numeric +
String/GUID/ByteString) + per-CallMethod allowlists.

## Probe

OPC-UA TCP `HEL` (Hello) message with the operator's endpoint
URL. Classifies the response as `ACK` (full server), `ERR`
(typed status code), or non-UA bytes (port repurposed). The
8-byte UA-TCP header parser is in
`internal/protocols/opcua/wire/`.

## Default-build refusal posture

The default proxy parses each MSG chunk's service TypeID; any
mutating service (`WriteRequest 673`, `CallRequest 704`)
short-circuits to a UA `ServiceFault` with status code
`BadUserAccessDenied (0x80100000)`. Reads (`ReadRequest 631`,
`BrowseRequest 527`, etc.) and transport-level frames (HEL /
OPN / CLO) always pass.

## Offensive write-gate

Three layers, each opt-in. Writes are gated at the TypeID +
the per-NodeId + (for CallRequest) per-(object, method) tuple.

### Service TypeID — v1.2

```
--service 673        # WriteRequest
--service 704        # CallRequest
```

### Per-NodeId — v1.6 + v1.12 chunk 3

For `WriteRequest 673`: every `WriteValue.NodeId` in the request
batch must match the allowlist (v1.12 chunk 2 walks the entire
`NodesToWrite` array; v1.6 chunk 2 only checked the first).

```
--node-id "ns=2;i=42"                           # numeric (v1.6+)
--node-id "ns=2;s=Temperature"                  # string  (v1.12+)
--node-id "ns=1;g=6B29FC40CA471067B31D00DD010662DA"  # GUID    (v1.12+)
--node-id "ns=3;b=DEADBEEF"                     # ByteString (v1.12+)
```

GUID accepts dashed input (`6b29fc40-ca47-1067-b31d-00dd010662da`)
and normalises to uppercase. ByteString must be even-length hex.

### Per-CallMethod — v1.12 chunk 6

For `CallRequest 704`: every `(ObjectId, MethodId)` pair in the
`MethodsToCall` array must be in the allowlist. Both NodeIds are
matched in canonical-string form (same encodings as `--node-id`).

```
--call-method "object=ns=2;i=100;method=ns=2;i=101"
--call-method "object=ns=3;s=DeviceFolder;method=ns=3;s=Restart"
```

### Refusal

UA `ServiceFault` MSG with status `BadUserAccessDenied`. Real UA
clients parse this as a normal access-denied error and don't
retry blindly.

## Operator example

```sh
elsereno-offensive write opcua dry-run \
  --target plc.internal:4840 \
  --service 673 --service 704 \
  --node-id "ns=2;i=42" \
  --node-id "ns=2;s=Temperature" \
  --call-method "object=ns=2;i=100;method=ns=2;i=101" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/opcua-gate.yaml
```

YAML keys: `services:`, `node_ids:` (`{namespace, identifier}`
or `{canonical: "ns=…;…=…"}`), `call_methods:`
(`{object, method}`).

## See also

- `.context/protocols/opcua.md` for engineering wire notes.
- v1.6.0 / v1.12.0 snapshots for the per-NodeId / rich-NodeId /
  CallMethod rationale.
