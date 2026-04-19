//go:build offensive

package main

// Blank imports register offensive exploit modules. The module's
// init() calls exploits.Register(). The CLI's `elsereno exploit
// list` walks the registry so every CVE that needs to be visible
// must be imported here.
import (
	_ "local/elsereno/offensive/exploits/cve_2015_5374"
	_ "local/elsereno/offensive/exploits/cve_2019_10953"
)
