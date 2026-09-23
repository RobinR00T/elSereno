package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/protocols/goose"
)

// newGooseCmd is the verb tree for IEC 61850 GOOSE / SV (substation-bus
// L2) dissection + passive anomaly monitoring. Like `profinet`, it is an
// OFFLINE workflow: feed it frames captured with tcpdump / tshark. Live
// L2 capture (raw sockets + CAP_NET_RAW) stays vNext.
//
//	elsereno goose decode  --hex 0x...        dissect one frame
//	elsereno goose monitor --file frames.txt  run the anomaly monitor
func newGooseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "goose",
		Short: "IEC 61850 GOOSE/SV L2 dissector + passive spoofing monitor (offline)",
	}
	cmd.AddCommand(newGooseDecodeCmd())
	cmd.AddCommand(newGooseMonitorCmd())
	return cmd
}

func newGooseDecodeCmd() *cobra.Command {
	var hexStr, file string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Dissect one GOOSE/SV Ethernet frame from hex or file",
		Long: `Reads a full Ethernet frame (dst+src+ethertype+payload; an
802.1Q VLAN tag is handled automatically) and prints the parsed GOOSE
IECGoosePdu or SV savPdu identity fields.

Examples:

  elsereno goose decode --hex '010ccd010001001122334455 88b8 ...'
  elsereno goose decode --file goose.bin --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			frame, err := loadProfinetFrame(hexStr, file) // shared hex/file loader
			if err != nil {
				return err
			}
			f, err := goose.Dissect(frame)
			if err != nil {
				return fmt.Errorf("dissect: %w", err)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(f)
			}
			cmd.Println(f.String())
			return nil
		},
	}
	cmd.Flags().StringVar(&hexStr, "hex", "", "hex string of the whole Ethernet frame (whitespace / 0x / : tolerated)")
	cmd.Flags().StringVar(&file, "file", "", "binary capture file of one Ethernet frame")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the parsed frame as JSON")
	return cmd
}

func newGooseMonitorCmd() *cobra.Command {
	var file string
	var jsonOut bool
	var jumpThreshold uint32
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Run the GOOSE/SV anomaly monitor over a sequence of frames",
		Long: `Reads a frame stream (one hex-encoded Ethernet frame per line;
blank lines and lines starting with '#' are ignored) and runs the
passive monitor over it in order. It flags the GOOSE-spoofing tells:
stNum jumps / regressions (the classic high-stNum override), the
simulation/test bit, ndsCom, confRev changes, sqNum stalls, and SV
smpCnt regressions.

Produce the input with, e.g.:

  tshark -r substation.pcap -Y 'goose || sv' -T fields -e frame.raw > frames.txt

Example:

  elsereno goose monitor --file frames.txt
  elsereno goose monitor --file frames.txt --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return errors.New("--file is required (one hex frame per line)")
			}
			return runGooseMonitor(cmd, file, jumpThreshold, jsonOut)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "frame stream: one hex-encoded Ethernet frame per line")
	cmd.Flags().Uint32Var(&jumpThreshold, "stnum-jump-threshold", 1, "largest stNum increment treated as normal (above it raises stnum_jump)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit each anomaly event as a JSON line (NDJSON)")
	return cmd
}

func runGooseMonitor(cmd *cobra.Command, file string, jumpThreshold uint32, jsonOut bool) error {
	fh, err := os.Open(file) // #nosec G304 -- operator-supplied path by design
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer func() { _ = fh.Close() }()

	m := goose.NewMonitor()
	m.StNumJumpThreshold = jumpThreshold
	enc := json.NewEncoder(cmd.OutOrStdout())

	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lineNo, frames, anomalies int
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
		f, err := goose.Dissect(raw)
		if err != nil {
			// Non-substation / malformed frames are skipped, not fatal:
			// a real capture is mixed traffic.
			continue
		}
		frames++
		for _, ev := range m.Observe(f) {
			anomalies++
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
		cmd.Printf("processed %d GOOSE/SV frames, %d anomaly events\n", frames, anomalies)
	}
	return nil
}
