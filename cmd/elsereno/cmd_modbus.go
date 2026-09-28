package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/protocols/modbus"
	mbwire "local/elsereno/internal/protocols/modbus/wire"
)

// newModbusCmd is the top-level verb for passive Modbus/TCP tooling.
// (Modbus writes/proxying live under `write modbus` and `proxy --plugin
// modbus`; this groups the read-only monitor.)
//
//	elsereno modbus monitor --file frames.txt
func newModbusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "modbus",
		Short: "Modbus/TCP passive monitor: flag writes, dangerous diagnostics and exceptions from a capture",
	}
	cmd.AddCommand(newModbusMonitorCmd())
	return cmd
}

func newModbusMonitorCmd() *cobra.Command {
	var file string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Passively flag Modbus/TCP writes + dangerous diagnostics from a capture (offline)",
		Long: `Reads a Modbus/TCP frame stream (one hex-encoded MBAP+PDU per
line; blank lines and '#' comments ignored) and reports the mutations
that crossed the link. Modbus authenticates nothing, so every write is a
reportable exposure event: whoever sent it never had to prove who they
were. This is the passive counterpart to the offensive write-gate (which
sits inline and blocks).

Produce the input with, e.g.:

  tshark -r plant.pcap -Y mbtcp -T fields -e tcp.payload > frames.txt

Examples:

  elsereno modbus monitor --file frames.txt
  elsereno modbus monitor --file frames.txt --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return errors.New("--file is required (one hex MBAP+PDU per line)")
			}
			return runModbusMonitor(cmd, file, jsonOut)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "frame stream: one hex-encoded Modbus/TCP frame (MBAP+PDU) per line")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit each event as a JSON line (NDJSON)")
	return cmd
}

func runModbusMonitor(cmd *cobra.Command, file string, jsonOut bool) error {
	fh, err := os.Open(file) // #nosec G304 -- operator-supplied path by design
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer func() { _ = fh.Close() }()

	m := modbus.NewMonitor()
	enc := json.NewEncoder(cmd.OutOrStdout())
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lineNo, frames, events int
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := decodeHexLoose(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		f, err := mbwire.ReadFrame(bytes.NewReader(raw))
		if err != nil {
			continue // malformed / partial: skip, a real capture is messy
		}
		frames++
		for _, ev := range m.Observe(f) {
			events++
			if jsonOut {
				if err := enc.Encode(ev); err != nil {
					return err
				}
			} else {
				cmd.Printf("frame %d: %s\n", frames, ev.String())
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	if !jsonOut {
		cmd.Printf("processed %d Modbus frames, %d events\n", frames, events)
	}
	return nil
}
