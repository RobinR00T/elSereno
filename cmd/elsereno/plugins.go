package main

// Blank imports below trigger init() registration of the default
// (read-only) plugin set. Offensive plugins are registered in
// plugins_offensive.go, behind the `offensive` build tag.
//
// No plugins are imported in F0; they appear from F2 onwards.
//
// Example (F2+):
//
//  import _ "local/elsereno/internal/protocols/modbus"
//  import _ "local/elsereno/internal/protocols/xot"
//  import _ "local/elsereno/internal/protocols/atmodem"
