package main

import (
	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/atg"
	"local/elsereno/internal/protocols/atmodem"
	"local/elsereno/internal/protocols/bacnet"
	"local/elsereno/internal/protocols/banner"
	"local/elsereno/internal/protocols/cwmp"
	"local/elsereno/internal/protocols/dnp3"
	"local/elsereno/internal/protocols/enip"
	"local/elsereno/internal/protocols/finsudp"
	"local/elsereno/internal/protocols/fox"
	"local/elsereno/internal/protocols/gesrtp"
	"local/elsereno/internal/protocols/hartip"
	"local/elsereno/internal/protocols/iax2"
	"local/elsereno/internal/protocols/iec104"
	"local/elsereno/internal/protocols/knxip"
	"local/elsereno/internal/protocols/mbustcp"
	"local/elsereno/internal/protocols/modbus"
	"local/elsereno/internal/protocols/opcua"
	"local/elsereno/internal/protocols/pbxhttp"
	"local/elsereno/internal/protocols/s7"
	"local/elsereno/internal/protocols/sip"
	"local/elsereno/internal/protocols/slmp"
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
	core.Register(core.Plugin{PluginMetadata: sip.Default().Metadata(), Factory: func() core.Protocol { return sip.Default() }})
	core.Register(core.Plugin{PluginMetadata: iax2.Default().Metadata(), Factory: func() core.Protocol { return iax2.Default() }})
	core.Register(core.Plugin{PluginMetadata: pbxhttp.Default().Metadata(), Factory: func() core.Protocol { return pbxhttp.Default() }})
	core.Register(core.Plugin{PluginMetadata: cwmp.Default().Metadata(), Factory: func() core.Protocol { return cwmp.Default() }})
	core.Register(core.Plugin{PluginMetadata: finsudp.Default().Metadata(), Factory: func() core.Protocol { return finsudp.Default() }})
	core.Register(core.Plugin{PluginMetadata: slmp.Default().Metadata(), Factory: func() core.Protocol { return slmp.Default() }})
	core.Register(core.Plugin{PluginMetadata: gesrtp.Default().Metadata(), Factory: func() core.Protocol { return gesrtp.Default() }})
	core.Register(core.Plugin{PluginMetadata: knxip.Default().Metadata(), Factory: func() core.Protocol { return knxip.Default() }})
	core.Register(core.Plugin{PluginMetadata: mbustcp.Default().Metadata(), Factory: func() core.Protocol { return mbustcp.Default() }})
}
