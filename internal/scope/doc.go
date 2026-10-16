// Package scope parses and evaluates scope.yaml. Callers apply ranges
// and ports (Check: scan and serve's scan runner) and dial blacklists
// (CheckDial: dial); protocols, binds and canary are parsed but no caller
// applies them (CheckProtocol has none). A scope applies only when a
// command is given --scope: nothing loads scope.yaml on its own.
package scope
