// Package scope parses and evaluates scope.yaml. Every network command
// given --scope applies ranges and ports (Check, CheckAddr, CheckPort)
// and the protocols lists (CheckPlugin) before it connects, through
// cmd/elsereno/scope_gate.go; dial applies its blacklist (CheckDial).
// Binds and canary are parsed but no caller applies them. A scope
// applies only when a command is given --scope: nothing loads
// scope.yaml on its own.
package scope
