# Niagara Fox (Tridium, ports 1911 + 4911)

Tridium Niagara framework (JACE, WebSupervisor) runs Building
Automation Systems on top of the proprietary "fox" protocol. BMS
dealers, HVAC contractors, hospital facility teams deploy it
widely, often exposed to the Internet.

## Probe

- Open TCP/1911 and send the client hello nmap's `fox-info.nse` sends
  (`fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n`). A
  station says nothing until a client says hello: in the real session
  of w3h/icsmaster `fox_info.pcap` the Workbench speaks first.
- Read up to 8 KiB. The reply is a station's Fox message when it starts
  with `fox a 0` (a client's start `fox a 1`) and carries a `{`
  dictionary, the same check as the NSE. A reflected copy of our hello
  is rejected.
- Until 2026-10-07 the probe only listened and sent nothing, and
  matched `fox a ` or `fox.version=` anywhere in what it read: a real
  station never answered, so the plugin never confirmed one (PITF-078).
- 4911 is Fox over TLS; the plugin speaks plain Fox on 1911.

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
