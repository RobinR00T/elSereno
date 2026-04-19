// Command atmodem-sim is a minimal AT-modem TCP responder for the
// integration suite. It speaks a scripted subset of Hayes + GSM and
// rejects the write-side commands ElSereno treats as forbidden.
//
// Usage:
//
//	atmodem-sim --listen 127.0.0.1:9999 --vendor siemens
//
// Flags let the operator flip between three personalities:
// `--vendor=siemens` / `--vendor=nokia` / `--vendor=kone` (EN 81-28).
package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type script map[string]string

var personas = map[string]script{
	"siemens": {
		"AT":      "OK",
		"ATI":     "Siemens TC35i\r\nREVISION 04.04\r\nOK",
		"AT+CGMI": "Siemens\r\nOK",
		"AT+CGMM": "TC35i\r\nOK",
	},
	"nokia": {
		"AT":      "OK",
		"ATI":     "Nokia Mobile Phones\r\n30A\r\nOK",
		"AT+CGMI": "Nokia\r\nOK",
	},
	"kone": {
		// EN 81-28 lift interphones announce themselves on connect.
		"AT":  "OK",
		"ATI": "KONE KCE-5500 lift-interphone\r\nOK",
	},
	"generic": {
		"AT":  "OK",
		"ATI": "GENERIC-HAYES v1\r\nOK",
	},
}

func main() {
	os.Exit(runMain())
}

func runMain() int {
	listen := flag.String("listen", "127.0.0.1:9999", "bind address")
	vendor := flag.String("vendor", "siemens", "persona: siemens|nokia|kone|generic")
	banner := flag.String("banner", "", "optional banner emitted on connect")
	flag.Parse()

	persona, ok := personas[*vendor]
	if !ok {
		log.Printf("unknown vendor %q (options: siemens nokia kone generic)", *vendor)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		log.Printf("listen %s: %v", *listen, err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	log.Printf("atmodem-sim listening on %s (vendor=%s)", *listen, *vendor)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			log.Printf("accept: %v", err)
			continue
		}
		go serve(ctx, conn, persona, *banner)
	}
}

func serve(ctx context.Context, conn net.Conn, persona script, banner string) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if banner != "" {
		_, _ = conn.Write([]byte(banner + "\r\n"))
	}

	rd := bufio.NewReader(conn)
	for {
		if ctx.Err() != nil {
			return
		}
		line, err := rd.ReadString('\r')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if cmd == "" {
			continue
		}
		// Refuse the full write/dial set that the default-build proxy
		// would also refuse. The simulator is deliberately more paranoid
		// than a real modem so tests never accidentally "dial".
		if isForbidden(cmd) {
			_, _ = conn.Write([]byte("ERROR\r\n"))
			continue
		}
		resp, ok := persona[cmd]
		if !ok {
			_, _ = conn.Write([]byte("ERROR\r\n"))
			continue
		}
		_, _ = conn.Write([]byte(resp + "\r\n"))
	}
}

func isForbidden(cmd string) bool {
	upper := strings.ToUpper(cmd)
	prefixes := []string{"ATD", "ATA", "AT+CMGS", "AT+CMGW", "AT+CMSS", "AT+CMGD", "AT+CFUN", "AT+CPWROFF", "+++"}
	for _, p := range prefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}
