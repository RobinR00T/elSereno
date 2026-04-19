// Package proxy is the generic TCP interception framework. Protocol
// plugins implement core.ProxyHandler; the framework wires their
// handlers onto a listener with per-connection pre/post hooks that
// can log, measure, or mutate traffic.
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
// F3 ships the TCP variant; UDP plugs in via a thin wrapper around
// net.ListenPacket that invokes the same hook chain per datagram
// (arrives with a protocol that actually needs it; Modbus is
// TCP-only).
package proxy
