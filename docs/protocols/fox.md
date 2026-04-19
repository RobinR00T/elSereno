# Niagara Fox (Tridium, ports 1911 + 4911)

Tridium Niagara framework (JACE, WebSupervisor) runs Building
Automation Systems on top of the proprietary "fox" protocol. BMS
dealers, HVAC contractors, hospital facility teams deploy it
widely — often exposed to the Internet.

## Probe

- Open TCP and read up to 8 KiB.
- Match the greeting line:
  - Case-insensitive substring `fox a ` (as in `fox a 0 -1 fox
    hello ...`).
  - Or `fox.version=` in the response body.

## Proxy policy (default build)

Fail-closed. Fox is a line-oriented administrative protocol; any
client byte can mutate state or initiate a session hijack. The
default `fox.ProxyHandler()` writes
`fox a 0 -1 fox denied\n` to the client and closes the
connection. A proper fox-aware proxy (allowing the hello handshake
but refusing everything else) lands with the offensive-build
WriteGatedHandler in F6+.

## Writes (`-tags offensive`)

Deferred to F6+. The offensive Fox plugin will allow the `fox a 0
-1 fox hello` handshake and route subsequent commands through
triple-confirm.

## Scope

- Tridium JACE controllers (R2, JACE-3e, JACE-8000).
- Niagara N4 / AX WebSupervisors.
- Impact: full Building Automation System admin (delete points,
  rewrite schedules, disable alarms).

## Public references

- Tridium published Niagara dev guide (Fox protocol minimal).
- Shodan banner search: `port:1911,4911 "fox a 0"`.
