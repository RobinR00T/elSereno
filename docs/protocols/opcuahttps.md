# OPC UA HTTPS (binary binding)

**Default port**: 4843/tcp (`opc.https`).
**Status**: fingerprint probe + write-gated proxy.
**Offensive build**: service-TypeID + per-NodeId (numeric +
String/GUID/ByteString) + per-CallMethod allowlists, identical to the
OPC UA TCP gate; transport-scoped confirm-token.

## Transport

The OPC UA HTTPS binding (Part 6 §7.4) carries each UA service request
as an HTTP `POST` body: a *bare* UA-Binary message. The message TypeId
(a NodeId) sits at offset 0, followed by the RequestHeader and the
service fields, with none of the `opc.tcp` SecureChannel framing
(SecureChannelId + TokenId + SequenceNumber + RequestId) that precedes
the TypeId on the TCP transport.

The write-gate reuses the validated `opc.tcp` parsers unchanged by
splicing a 16-byte zero prefix in front of the bare body (see
`internal/protocols/opcua/wire/https.go`: `ServiceTypeIDHTTPS`,
`WriteRequestAllNodesRichHTTPS`, `CallRequestAllMethodsHTTPS`). No wire
parser is forked.

## Probe (default build)

`POST /discovery` (and a real `GetEndpoints` POST to `/`) over TLS.
When the server returns a decodable `GetEndpointsResponse`, the finding
carries the endpoint list and its security posture; a
`SecurityMode=None` endpoint (anonymous, unencrypted UA access) scores
as higher exposure. Certificates are never verified: this fingerprints
untrusted hosts, it does not trust them.

## Offensive write-gate

The gate reads each POST body, classifies the service, and decides:

- **Non-POST** (GET / HEAD / OPTIONS) and **non-mutating services**
  (Read, Browse, GetEndpoints, session management) always pass.
- **`WriteRequest 673`** and **`CallRequest 704`** pass only when the
  service TypeID is in the allowlist AND, when a per-node / per-method
  allowlist is set, every target matches. Unparseable bodies fail
  closed.
- **Refusal** is a UA `ServiceFault` (`BadUserAccessDenied
  0x80100000`) returned as the HTTP `200` body with Content-Type
  `application/octet-stream`, plus an `X-Elsereno-Gate-Reason` header.
  A real UA client decodes a parseable service error, exactly as the
  OPC UA TCP gate returns a `ServiceFault` MSG rather than a TCP RST.

The allowlist dimensions and hash ladder are shared verbatim with the
OPC UA TCP gate (`offensive/write/opcua`); see
[opcua.md](opcua.md) for the per-NodeId / per-CallMethod semantics.

### TLS

Like the `pbxhttp` gate, TLS is a **deployment concern**: the gate
inspects the HTTP + UA-Binary application layer. Terminate TLS in front
of the gate, or point it at a plaintext upstream. The gate does not
man-in-the-middle a TLS session itself.

### Token scope

The confirm-token is scoped to protocol `opcuahttps`: a token minted
for the OPC UA TCP gate does **not** authorise HTTPS writes, and vice
versa, even for an identical allowlist. Different transport, different
exposure.

## CLI

Derive the session token (mirrors `write opcua`):

```
elsereno write opcuahttps proxy-dry-run \
  --target plc.example:4843 \
  --service 673 \
  --node-id "ns=2;i=42" \
  --vault-passphrase-file ./vault.pass
```

Run the gate (any subset of the allowlist flags the token was minted
with):

```
elsereno proxy listen --plugin opcuahttps \
  --listen 127.0.0.1:4843 --target plc.example:4843 \
  --service 673 --node-id "ns=2;i=42" \
  --accept-writes --confirm-target plc.example:4843 \
  --confirm-token <token> \
  --vault-passphrase-file ./vault.pass
```

Sessions can be captured with `--record FILE` (NDJSON,
`schema=elsereno-replay/v1`).
