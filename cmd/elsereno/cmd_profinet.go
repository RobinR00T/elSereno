package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/protocols/profinet"
)

// newProfinetCmd is the v2.41+ verb tree for PROFINET DCP
// codec operations. Subcommands:
//
//	elsereno profinet decode --hex 0xFE...     decode a hex string
//	elsereno profinet decode --file frame.bin  decode from file
//	elsereno profinet encode-identify --xid N  emit hex Identify-All request
//
// Live L2 capture remains vNext (requires raw sockets +
// CAP_NET_RAW); the offline-decode workflow lets operators
// inventory a PROFINET segment via tcpdump + this verb.
func newProfinetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profinet",
		Short: "PROFINET DCP wire codec (v2.41+; offline decode + Identify-All encode)",
	}
	cmd.AddCommand(newProfinetDecodeCmd())
	cmd.AddCommand(newProfinetEncodeIdentifyCmd())
	return cmd
}

func newProfinetDecodeCmd() *cobra.Command {
	var (
		hexStr  string
		file    string
		jsonOut bool
		stripL2 int
	)
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Decode a PROFINET DCP frame from hex or file",
		Long: `Reads a DCP frame (everything AFTER the 14-byte Ethernet
header by default; use --strip-l2 18 for VLAN-tagged
captures) and prints the parsed Header + Blocks + (for
Identify responses) the flattened IdentifyResponse summary.

Examples:

  # Decode from inline hex (paste from tcpdump -xx output).
  elsereno profinet decode --hex 'feff0501cafebabe00000018020200110000...'

  # Decode from a binary capture (e.g. tshark -w identify.bin).
  elsereno profinet decode --file identify.bin

  # JSON output (machine-readable; pipe through jq).
  elsereno profinet decode --file identify.bin --json
`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			frame, err := loadProfinetFrame(hexStr, file)
			if err != nil {
				return err
			}
			if stripL2 > 0 {
				if stripL2 > len(frame) {
					return fmt.Errorf("strip-l2=%d exceeds frame length %d", stripL2, len(frame))
				}
				frame = frame[stripL2:]
			}
			f, decErr := profinet.DecodeDCP(frame)
			// Partial result preserved by decoder; print whatever
			// we got even on truncation error, then surface err.
			if f == nil && decErr != nil {
				return decErr
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				return renderProfinetJSON(out, f, decErr)
			}
			renderProfinetText(out, f, decErr)
			return nil
		},
	}
	cmd.Flags().StringVar(&hexStr, "hex", "", "inline hex (whitespace + 0x prefix tolerated)")
	cmd.Flags().StringVar(&file, "file", "", "path to binary capture file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "render as JSON instead of human-friendly text")
	cmd.Flags().IntVar(&stripL2, "strip-l2", 0, "bytes to strip before decoding (14 = Ethernet, 18 = VLAN)")
	return cmd
}

func newProfinetEncodeIdentifyCmd() *cobra.Command {
	var xid uint32
	cmd := &cobra.Command{
		Use:   "encode-identify",
		Short: "Emit hex bytes for a DCP Identify-All request",
		Long: `Prints an 18-byte DCP RT frame (no Ethernet header) that
matches every PROFINET device on the segment. Operators
piping this into a raw-socket sender (gopacket/scapy) can
trigger Identify responses without writing the encoder
themselves.

Default XID is 0xCAFEBABE for visual recognition in pcap.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := profinet.EncodeDCPIdentifyAll(xid)
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), hex.EncodeToString(out))
			return nil
		},
	}
	cmd.Flags().Uint32Var(&xid, "xid", 0xCAFEBABE, "transaction-ID embedded in the request")
	return cmd
}

// loadProfinetFrame reads from --hex or --file. Exactly one
// must be supplied; both empty → error; both set → error.
func loadProfinetFrame(hexStr, file string) ([]byte, error) {
	switch {
	case hexStr == "" && file == "":
		return nil, errors.New("either --hex or --file must be set")
	case hexStr != "" && file != "":
		return nil, errors.New("--hex and --file are mutually exclusive")
	case hexStr != "":
		return decodeHexLoose(hexStr)
	default:
		return readFile(file)
	}
}

// decodeHexLoose tolerates whitespace, 0x prefix, and the
// `:` separator some tcpdump variants emit.
func decodeHexLoose(s string) ([]byte, error) {
	clean := strings.NewReplacer(
		" ", "", "\t", "", "\n", "", "\r", "",
		":", "", "-", "", "0x", "", "0X", "",
	).Replace(s)
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex has odd length %d after cleanup", len(clean))
	}
	return hex.DecodeString(clean)
}

// readFile loads a binary capture from disk. #nosec G304 —
// operator-supplied path by design.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	const maxFrameSize = 64 * 1024
	return io.ReadAll(io.LimitReader(f, maxFrameSize))
}

// renderProfinetText prints a human-readable digest.
func renderProfinetText(out io.Writer, f *profinet.Frame, decErr error) {
	if f == nil {
		_, _ = fmt.Fprintf(out, "decode failed: %v\n", decErr)
		return
	}
	_, _ = fmt.Fprintf(out, "DCP Frame\n")
	_, _ = fmt.Fprintf(out, "  FrameID:      0x%04X\n", f.Header.FrameID)
	_, _ = fmt.Fprintf(out, "  ServiceID:    0x%02X (%s)\n", f.Header.ServiceID, profinetServiceName(f.Header.ServiceID))
	_, _ = fmt.Fprintf(out, "  ServiceType:  0x%02X (%s)\n", f.Header.ServiceType, profinetServiceTypeName(f.Header.ServiceType))
	_, _ = fmt.Fprintf(out, "  XID:          0x%08X\n", f.Header.XID)
	_, _ = fmt.Fprintf(out, "  DataLength:   %d\n", f.Header.DataLength)
	_, _ = fmt.Fprintf(out, "  Blocks: %d\n", len(f.Blocks))
	for i, b := range f.Blocks {
		_, _ = fmt.Fprintf(out, "    [%d] Option=0x%02X(%s) Sub=0x%02X Length=%d BlockInfo=0x%04X DataLen=%d\n",
			i, b.Option, profinetOptionName(b.Option), b.Suboption, b.Length, b.BlockInfo, len(b.Data))
	}
	// For Identify responses, print the flat summary.
	if f.Header.FrameID == profinet.FrameIDIdentifyResponse {
		resp := profinet.ParseIdentifyResponse(f)
		_, _ = fmt.Fprintf(out, "\nIdentify summary:\n")
		_, _ = fmt.Fprintf(out, "  NameOfStation: %s\n", resp.NameOfStation)
		_, _ = fmt.Fprintf(out, "  VendorID:      0x%04X\n", resp.VendorID)
		_, _ = fmt.Fprintf(out, "  DeviceID:      0x%04X\n", resp.DeviceID)
		_, _ = fmt.Fprintf(out, "  Role:          %s (0x%02X)\n", profinet.FormatDeviceRole(resp.DeviceRole), resp.DeviceRole)
		if resp.OEMDeviceID != "" {
			_, _ = fmt.Fprintf(out, "  OEMDeviceID:   %s\n", resp.OEMDeviceID)
		}
		if resp.IP != nil {
			_, _ = fmt.Fprintf(out, "  IP:            %s\n", resp.IP)
			_, _ = fmt.Fprintf(out, "  Subnet:        %s\n", resp.Subnet)
			_, _ = fmt.Fprintf(out, "  Gateway:       %s\n", resp.Gateway)
		}
	}
	if decErr != nil {
		_, _ = fmt.Fprintf(out, "\n(partial decode: %v)\n", decErr)
	}
}

// renderProfinetJSON emits a stable JSON shape so operators
// can pipe into jq / dashboards.
func renderProfinetJSON(out io.Writer, f *profinet.Frame, decErr error) error {
	payload := map[string]any{
		"header": map[string]any{
			"frame_id":     f.Header.FrameID,
			"service_id":   f.Header.ServiceID,
			"service_type": f.Header.ServiceType,
			"xid":          f.Header.XID,
			"data_length":  f.Header.DataLength,
		},
		"blocks":       f.Blocks,
		"decode_error": errString(decErr),
	}
	if f.Header.FrameID == profinet.FrameIDIdentifyResponse {
		resp := profinet.ParseIdentifyResponse(f)
		payload["identify_summary"] = map[string]any{
			"name_of_station": resp.NameOfStation,
			"vendor_id":       resp.VendorID,
			"device_id":       resp.DeviceID,
			"device_role":     resp.DeviceRole,
			"device_role_str": profinet.FormatDeviceRole(resp.DeviceRole),
			"oem_device_id":   resp.OEMDeviceID,
			"ip":              ipString(resp.IP),
			"subnet":          ipString(resp.Subnet),
			"gateway":         ipString(resp.Gateway),
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func ipString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func profinetServiceName(id uint8) string {
	switch id {
	case profinet.ServiceGet:
		return "Get"
	case profinet.ServiceSet:
		return "Set"
	case profinet.ServiceIdentify:
		return "Identify"
	case profinet.ServiceHello:
		return "Hello"
	default:
		return "?"
	}
}

func profinetServiceTypeName(t uint8) string {
	switch t {
	case profinet.ServiceTypeRequest:
		return "Request"
	case profinet.ServiceTypeResponse:
		return "Response"
	default:
		return "?"
	}
}

func profinetOptionName(o uint8) string {
	switch o {
	case profinet.OptionIP:
		return "IP"
	case profinet.OptionDevice:
		return "Device"
	case profinet.OptionDHCP:
		return "DHCP"
	case profinet.OptionControl:
		return "Control"
	case profinet.OptionAll:
		return "All"
	default:
		return "?"
	}
}
