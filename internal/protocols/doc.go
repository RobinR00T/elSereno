// Package protocols is the parent of per-protocol plugins. It has no
// code of its own: sub-packages register in init() via
// core.Register(...) and are included via blank imports from
// cmd/elsereno/plugins.go (default) or plugins_offensive.go
// (-tags offensive). See ADR-009.
package protocols
