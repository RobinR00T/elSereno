// Package fox implements the ElSereno plugin for Niagara Fox
// (Tridium) on ports 1911 and 4911. Niagara Fox answers each new
// TCP connection with an ASCII banner ("fox a 0 -1 fox hello\n...")
// that carries fox.version, host id, and capability strings.
package fox
