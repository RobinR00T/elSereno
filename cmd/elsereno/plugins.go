package main

import (
	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/atg"
	"local/elsereno/internal/protocols/atmodem"
	"local/elsereno/internal/protocols/bacnet"
	"local/elsereno/internal/protocols/banner"
	"local/elsereno/internal/protocols/dnp3"
	"local/elsereno/internal/protocols/enip"
	"local/elsereno/internal/protocols/fox"
	"local/elsereno/internal/protocols/hartip"
	"local/elsereno/internal/protocols/iec104"
	"local/elsereno/internal/protocols/modbus"
	"local/elsereno/internal/protocols/opcua"
	"local/elsereno/internal/protocols/s7"
	"local/elsereno/internal/protocols/xot"
)

// init registers the default (read-only) plugin set. Offensive plugins
// are registered in plugins_offensive.go behind the `offensive` build
// tag (ADR-004, ADR-009).
func init() {
	core.Register(core.Plugin{PluginMetadata: banner.Default().Metadata(), Factory: func() core.Protocol { return banner.Default() }})
	core.Register(core.Plugin{PluginMetadata: xot.Default().Metadata(), Factory: func() core.Protocol { return xot.Default() }})
	core.Register(core.Plugin{PluginMetadata: atmodem.Default().Metadata(), Factory: func() core.Protocol { return atmodem.Default() }})
	core.Register(core.Plugin{PluginMetadata: modbus.Default().Metadata(), Factory: func() core.Protocol { return modbus.Default() }})
	core.Register(core.Plugin{PluginMetadata: s7.Default().Metadata(), Factory: func() core.Protocol { return s7.Default() }})
	core.Register(core.Plugin{PluginMetadata: enip.Default().Metadata(), Factory: func() core.Protocol { return enip.Default() }})
	core.Register(core.Plugin{PluginMetadata: bacnet.Default().Metadata(), Factory: func() core.Protocol { return bacnet.Default() }})
	core.Register(core.Plugin{PluginMetadata: dnp3.Default().Metadata(), Factory: func() core.Protocol { return dnp3.Default() }})
	core.Register(core.Plugin{PluginMetadata: iec104.Default().Metadata(), Factory: func() core.Protocol { return iec104.Default() }})
	core.Register(core.Plugin{PluginMetadata: hartip.Default().Metadata(), Factory: func() core.Protocol { return hartip.Default() }})
	core.Register(core.Plugin{PluginMetadata: fox.Default().Metadata(), Factory: func() core.Protocol { return fox.Default() }})
	core.Register(core.Plugin{PluginMetadata: atg.Default().Metadata(), Factory: func() core.Protocol { return atg.Default() }})
	core.Register(core.Plugin{PluginMetadata: opcua.Default().Metadata(), Factory: func() core.Protocol { return opcua.Default() }})
}
