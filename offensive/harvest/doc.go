//go:build offensive

// Package harvest collects credentials from Telnet, FTP, HTTP-Basic,
// and SNMPv1/2c and stores them in the encrypted vault. Compiled only
// with -tags offensive.
package harvest
