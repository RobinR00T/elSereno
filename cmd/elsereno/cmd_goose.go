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
	var file, iface string
	var jsonOut bool
	var jumpThreshold uint32
	var count uint
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Run the GOOSE/SV anomaly monitor over captured frames (--file) or a live interface (--iface, Linux)",
		Long: `Runs the passive GOOSE/SV anomaly monitor over either an
offline capture (--file) or a live interface (--iface, Linux only). It
flags the GOOSE-spoofing tells: stNum jumps / regressions (the classic
high-stNum override), the simulation/test bit, ndsCom, confRev changes,
sqNum stalls, and SV smpCnt regressions.

--file reads one hex-encoded Ethernet frame per line (blank lines and
'#' comments ignored). Produce it with, e.g.:

  tshark -r substation.pcap -Y 'goose || sv' -T fields -e frame.raw > frames.txt

--iface opens a receive-only AF_PACKET socket (needs CAP_NET_RAW) and
sniffs live. It never transmits. Off Linux it errors with a clear
message pointing back to --file.

Examples:

  elsereno goose monitor --file frames.txt --json
  sudo elsereno goose monitor --iface eth0
  sudo elsereno goose monitor --iface eth0 --count 500 --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (file == "") == (iface == "") {
				return errors.New("exactly one of --file or --iface is required")
			}
			st := newGooseMonitorState(cmd, jumpThreshold, jsonOut)
			if iface != "" {
				return runGooseLive(cmd, st, iface, count)
			}
			return runGooseFile(cmd, st, file)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "offline frame stream: one hex-encoded Ethernet frame per line")
	cmd.Flags().StringVar(&iface, "iface", "", "live capture: network interface to sniff (Linux only; needs CAP_NET_RAW)")
	cmd.Flags().UintVar(&count, "count", 0, "with --iface: stop after N GOOSE/SV frames (0 = run until Ctrl-C)")
	cmd.Flags().Uint32Var(&jumpThreshold, "stnum-jump-threshold", 1, "largest stNum increment treated as normal (above it raises stnum_jump)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit each anomaly event as a JSON line (NDJSON)")
	return cmd
}

// gooseMonitorState bundles the monitor + encoder + counters shared by
// the offline (--file) and live (--iface) paths so both classify,
// count, and print anomalies identically.
type gooseMonitorState struct {
	m         *goose.Monitor
	enc       *json.Encoder
	jsonOut   bool
	frames    int
	anomalies int
}

func newGooseMonitorState(cmd *cobra.Command, jumpThreshold uint32, jsonOut bool) *gooseMonitorState {
	m := goose.NewMonitor()
	m.StNumJumpThreshold = jumpThreshold
	return &gooseMonitorState{m: m, enc: json.NewEncoder(cmd.OutOrStdout()), jsonOut: jsonOut}
}

// handle dissects one raw Ethernet frame and prints any anomaly events.
// Non-GOOSE/SV or malformed frames are skipped (a real segment is mixed
// traffic), so only a print/encode failure returns an error.
func (s *gooseMonitorState) handle(cmd *cobra.Command, raw []byte) error {
	f, err := goose.Dissect(raw)
	if err != nil {
		return nil //nolint:nilerr // non-GOOSE/SV + malformed frames are skipped: a live segment is mixed traffic
	}
	s.frames++
	for _, ev := range s.m.Observe(f) {
		s.anomalies++
		if s.jsonOut {
			if err := s.enc.Encode(ev); err != nil {
				return err
			}
		} else {
			cmd.Printf("frame %d: %s\n", s.frames, ev.String())
		}
	}
	return nil
}

func (s *gooseMonitorState) summary(cmd *cobra.Command) {
	if !s.jsonOut {
		cmd.Printf("processed %d GOOSE/SV frames, %d anomaly events\n", s.frames, s.anomalies)
	}
}

func runGooseFile(cmd *cobra.Command, s *gooseMonitorState, file string) error {
	fh, err := os.Open(file) // #nosec G304 -- operator-supplied path by design
	if err != nil {
		return fmt.Errorf("open %s: %w", file, err)
	}
	defer func() { _ = fh.Close() }()

	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
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
		if err := s.handle(cmd, raw); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}
	s.summary(cmd)
	return nil
}

// runGooseLive sniffs iface with a passive AF_PACKET socket and feeds
// each frame through the monitor until the context is cancelled (Ctrl-C)
// or count frames have been seen. Linux only.
func runGooseLive(cmd *cobra.Command, s *gooseMonitorState, iface string, count uint) error {
	cap, err := goose.OpenLiveCapture(iface)
	if err != nil {
		return fmt.Errorf("live capture: %w", err)
	}
	defer func() { _ = cap.Close() }()
	if !s.jsonOut {
		cmd.Printf("listening on %s for GOOSE/SV (Ctrl-C to stop)\n", iface)
	}
	ctx := cmd.Context()
	for ctx.Err() == nil {
		if count > 0 && uint(s.frames) >= count { // #nosec G115 -- s.frames is a monotonic non-negative frame counter
			break
		}
		raw, err := cap.Read()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if raw == nil {
			continue // idle poll tick; loop re-checks ctx + count
		}
		if err := s.handle(cmd, raw); err != nil {
			return err
		}
	}
	s.summary(cmd)
	return nil
}
