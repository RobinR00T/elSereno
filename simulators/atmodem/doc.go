// Command atmodem-sim is a scripted AT-modem responder for the
// integration suite. It refuses every write/dial command so tests
// cannot accidentally exercise destructive code paths against it.
package main
