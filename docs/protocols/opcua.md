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

## Anonymous-access probe (active recon, read-only)

`elsereno opcua probe-anon --target host:port` goes past the fingerprint:
a `SecurityMode=None` endpoint only ADVERTISES anonymous access, so this
actively confirms it by driving the full session handshake:

```
HELLO -> OpenSecureChannel(None) -> GetEndpoints -> CreateSession -> ActivateSession(Anonymous)
```

If the final `ServiceResult` is `Good`, a stranger can open a session on
the server (`SessionOpened`). It reports whether the server is OPC UA,
whether it advertises an Anonymous `UserTokenPolicy` (and its `PolicyId`,
which varies per server: "0", "anonymous", ...), and whether the
anonymous session actually opened. It is read-only: it never reads or
writes the address space, only proves the session opens.

The session-establishment wire (OPN(None) / CreateSession /
ActivateSession encode + decode, all validated against a real captured
`SecurityPolicy#None` session) is in `internal/protocols/opcua/wire/`
(`session.go`, `response.go`); the client is
`internal/protocols/opcua/anonprobe.go` (`ProbeAnonymousAccess`, over an
`io.ReadWriter`). Idea from the `-probe-anon` check in the OT researcher
Christopher D.'s `chrisdinozzi/opcua-recon`.

## Writeable-tag walk (active recon, read-only)

`elsereno opcua probe-write --target host:port` goes one step past
`probe-anon`: it opens the anonymous session and then walks the address
space to find what that stranger could actually change. Starting from
ObjectsFolder (`i=85`) it browses forward HierarchicalReferences
breadth-first, descending into Objects/Views, and for every Variable it
meets it reads the `UserAccessLevel` attribute (id 18) and flags the ones
carrying the `CurrentWrite` bit: process tags an anonymous client could
write (a setpoint, a mode selector, an output).

```
probe-anon confirms:  a stranger can open a session.
probe-write answers:  ...and here are the tags that stranger can write.
```

It is strictly read-only: it reads the `NodeClass` (id 2, from Browse) and
`UserAccessLevel` (id 18) attributes, it never issues a Write. The walk is
bounded by `--max-nodes` (default 500: nodes tracked + folders browsed) so a
large or hostile address space cannot run away; when the cap is hit the
result is marked truncated.

The Browse + Read wire (`browse.go`, `read.go`, `nodeid.go`) and the walk
client (`writeprobe.go`, `session_client.go`, which reuses the session
established by `anonprobe.go`) live in `internal/protocols/opcua/`. Idea
from the `-probe-write` check in the OT researcher Christopher D.'s
`chrisdinozzi/opcua-recon`.

**Validation.** The session-establishment wire is validated byte for byte
against a real captured `SecurityPolicy#None` session. The Browse/Read codec
is grounded in OPC-UA Part 4 (services) + Part 6 (binary encoding); as of
2026-10-03 it is **also validated byte for byte against real captures**
(CISA cisagov/icsnpp-opcua-binary, open62541 stack): `ParseBrowseResponse`
against a real BrowseResponse (9 references parsed), and `ParseReadResponse`
against a real Int32 attribute read, plus confirmation that it fail-closes
(as designed) on a real non-integer (String/DiagnosticInfo) value. See
`internal/protocols/opcua/wire/browse_read_realcap_test.go`.

## Exposure as a scored Finding (opt-in plugin)

The same anonymous-access + writeable-walk read is also available as a
scored `core.Finding` through the `opcua-exposure` plugin, so the exposure
flows into the normal fingerprint/scan/scoring/triage pipeline:

```sh
elsereno fingerprint probe --plugin opcua-exposure --target plc:4840 --json
```

It is **opt-in**: its `DefaultPort` is 0, so the `discover`/`scan` default
sweep skips it (`plugins ports` shows only `opcua` on 4840). It runs only
when named with `--plugin opcua-exposure`, and does not change the default
`opcua` fingerprint (which still does HEL/ACK only). It reuses
`ProbeWriteableNodes` (which embeds `ProbeAnonymousAccess`), so it is the
same strictly read-only path: it opens an anonymous session and reads node
attributes, it never issues a Write. Scoring, by what the probe learned:

| State | Severity |
|-------|----------|
| Anonymous session opens **and** exposes anonymous-writeable tags | Critical (`exposure`/`auth_state` 95) |
| Anonymous session opens, no writeable tag found in the walked subtree | High |
| OPC UA confirmed but the anonymous session is rejected (auth enforced) | Medium |
| Not OPC UA | Medium (baseline) |

Plugin: `internal/protocols/opcua/exposureplugin.go`. It is the OPC UA
counterpart to the `s7-exposure` plugin (see [`s7.md`](s7.md)).

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

### Service TypeID, v1.2

```
--service 673        # WriteRequest
--service 704        # CallRequest
```

### Per-NodeId, v1.6 + v1.12 chunk 3

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

### Per-CallMethod, v1.12 chunk 6

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

## OPC UA over HTTPS

The HTTPS transport binding (Part 6 §7.4) is a **separate plugin**,
`opcuahttps` (TCP/4843). It POSTs a real GetEndpointsRequest over
TLS and parses the returned EndpointDescription list, so the finding
carries the server's security posture: a `SecurityMode=None`
endpoint (anonymous, unencrypted UA access) raises exposure and
auth_state. If the deep POST fails it falls back to an HTTP
header classifier. Drive it directly with:

```sh
elsereno fingerprint probe --plugin opcuahttps --target host:4843 --json
```

`scripts/demo-opcua-https-fingerprint.sh` runs it end-to-end against
a bundled TLS simulator. The GetEndpoints codec lives in
`internal/protocols/opcua/wire/getendpoints.go`.

## See also

- `.context/protocols/opcua.md` for engineering wire notes.
- v1.6.0 / v1.12.0 snapshots for the per-NodeId / rich-NodeId /
  CallMethod rationale.
