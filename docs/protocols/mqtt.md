# MQTT

**Default port**: 1883/tcp (plaintext); 8883/tcp probed over TLS.
**Status**: exposure fingerprint (probe).
**Build**: default (read-only recon).

## Why it matters

MQTT is the dominant OT-to-IT / Unified-Namespace message bus (it carries
Sparkplug B device data in most modern plants). Brokers are routinely
stood up with **anonymous access and no topic ACLs**, so "a stranger on
the network can read the entire plant, live" is a common, high-impact
misconfiguration, not a CVE.

## Probe

Read-only. The probe never PUBLISHes:

1. Sends an anonymous, clean-session **CONNECT** (MQTT 3.1.1). A broker
   that answers **CONNACK 0x00** allows anonymous access (the headline
   finding). `0x04` / `0x05` mean auth is required (still reported: the
   broker is exposed).
2. If anonymous is accepted, sends one **SUBSCRIBE to `#`** (the wildcard,
   every topic). A granted SUBACK means a stranger can read all topics.
3. If the wildcard is granted, reads any **PUBLISH** traffic for a short
   window and flags the **Sparkplug B** namespace (`spBv1.0/...`),
   confirming live device/plant data is flowing.

On 8883 the dial is wrapped in TLS (certificate not verified: this
fingerprints untrusted brokers, it does not trust them).

## Scoring

`auth_state` and `exposure` rise when anonymous access works; `capability`
rises when the wildcard subscription is granted (read-everything);
`impact_class` rises when Sparkplug B is confirmed (real OT data).

## Wire

MQTT 3.1.1 CONNECT / CONNACK / SUBSCRIBE / SUBACK, plus enough of PUBLISH
to read a topic name, are parsed from scratch in
`internal/protocols/mqtt/wire/` (no external MQTT library). Reference:
MQTT Version 3.1.1, OASIS Standard, 29 October 2014; Sparkplug B (Eclipse
Tahu) for the topic namespace.

Idea from the OT researcher Christopher D. (chrisdinozzi/opcua-recon),
whose Unified-Namespace lab post surfaced the MQTT/Sparkplug exposure
surface.

## Out of scope (vNext)

- Gated MQTT proxy (allowlist PUBLISH to control topics); today
  `ProxyHandler` denies all.
- Decoding Sparkplug B protobuf payloads (the probe only reads the topic).
