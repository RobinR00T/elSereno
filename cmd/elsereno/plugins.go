package main

import (
	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/atmodem"
	"local/elsereno/internal/protocols/banner"
	"local/elsereno/internal/protocols/xot"
)

// init registers the default (read-only) plugin set. Offensive plugins
// are registered in plugins_offensive.go behind the `offensive` build
// tag (ADR-004, ADR-009).
func init() {
	core.Register(core.Plugin{
		PluginMetadata: banner.Default().Metadata(),
		Factory:        func() core.Protocol { return banner.Default() },
	})
	core.Register(core.Plugin{
		PluginMetadata: xot.Default().Metadata(),
		Factory:        func() core.Protocol { return xot.Default() },
	})
	core.Register(core.Plugin{
		PluginMetadata: atmodem.Default().Metadata(),
		Factory:        func() core.Protocol { return atmodem.Default() },
	})
}
