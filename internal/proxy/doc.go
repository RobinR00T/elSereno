// Package proxy is the generic interception framework (TCP and UDP).
// Protocol plugins implement core.ProxyHandler; the framework wires
// their handlers onto a listener with per-connection pre/post hooks
// that can log, measure, or mutate traffic.
//
// Design choices:
//
//   - The framework owns the listener + Accept loop + graceful
//     shutdown; protocol plugins own nothing more than Handle.
//   - Hooks run per frame or per byte-chunk at the plugin's
//     discretion; the framework exposes a PreHook/PostHook pair
//     that lives on the connection for the session's lifetime.
//   - Rendering of target-controlled bytes is the hook's
//     responsibility — the framework passes raw bytes verbatim.
//     Hooks that log MUST run content through
//     internal/render.SafeBytes.
//
// Transport: Options.Network selects "tcp" (default, the F3 accept
// loop) or "udp". The UDP path (udp.go) binds one net.PacketConn and,
// per distinct client source address, dials a fresh upstream UDP
// socket and drives the same Handler.Handle(ctx, client, upstream)
// contract, one datagram per Read; idle sessions are reaped after
// IdleTimeout. finsudp (UDP/9600) uses it; Modbus and SLMP are TCP.
package proxy
