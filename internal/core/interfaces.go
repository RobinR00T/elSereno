package core

import (
	"context"
	"io"
)

// Protocol is implemented by each plugin under internal/protocols/<name>/.
// Plugins register themselves in init() (ADR-009).
type Protocol interface {
	// Metadata returns the plugin's static description.
	Metadata() PluginMetadata

	// Probe fingerprints a target. It must treat response bytes as
	// adversarial (see internal/render.SafeBytes).
	Probe(ctx context.Context, target Target) (*Finding, error)

	// REPL starts an interactive session over an established connection.
	REPL(ctx context.Context, session *Session) error

	// ProxyHandler returns the handler used by internal/proxy when this
	// protocol is proxied.
	ProxyHandler() ProxyHandler
}

// ProxyHandler is the low-level hook the proxy framework invokes per
// connection.
type ProxyHandler interface {
	Handle(ctx context.Context, client io.ReadWriter, upstream io.ReadWriter) error
}

// Input produces Targets (or bare addresses with ports) from an external
// source (Shodan, Censys, nmap XML, list file, stdin).
type Input interface {
	Name() string
	Read(ctx context.Context) (<-chan Target, <-chan error)
}

// Output writes a run's findings to a sink.
type Output interface {
	Name() string
	WriteFindings(ctx context.Context, findings <-chan Finding) error
}

// PluginMetadata is the static description of a Protocol plugin. It is
// exposed via `elsereno plugins list`.
type PluginMetadata struct {
	Name        string
	Description string
	DefaultPort Port
	Build       string // "default" | "offensive"
	Version     string
}

// Plugin is the registration wrapper.
type Plugin struct {
	PluginMetadata
	Factory func() Protocol
}
