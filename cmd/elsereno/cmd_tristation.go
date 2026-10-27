package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/pcapfile"
	"local/elsereno/internal/protocols/tristation"
	"local/elsereno/internal/protocols/tristation/wire"
	"local/elsereno/internal/render"
	"local/elsereno/internal/standards"
)

type tristationOpts struct {
	v               targetVerb
	active, passive bool
	file            string
	status          bool
}

// newTriStationCmd is the TriStation (Triconex SIS) verb:
//
//	elsereno tristation --passive --file capture.pcapng
//	elsereno tristation --active --target sis:1502 [--status]
func newTriStationCmd() *cobra.Command {
	var o tristationOpts
	cmd := &cobra.Command{
		Use:   "tristation",
		Short: "Triconex safety controller (TriStation, UDP/1502): passive capture analysis or active fingerprint",
		Long: `Looks at TriStation, the engineering protocol of Schneider Electric
Triconex safety instrumented systems (the protocol TRITON used in 2017).
Pick exactly one mode:

  --passive --file X   decode a pcap/pcapng capture offline: controllers
                       seen, commands by name, every command that changes
                       the safety program or run state (download, run,
                       halt, allocate...), and any CP status the
                       controller reported (key switch, run state,
                       project name and version). No packet is sent.

  --active --target H  send CONNECT, read the reply, send DISCONNECT. No
                       TriStation command is issued. Add --status to send
                       one read-only "Get CP status" and print the key
                       switch position: PROGRAM or REMOTE means the safety
                       program can be changed over the network.

A safety controller is the last layer between a process upset and harm
to people. Run --active only against controllers you are authorised to
test, ideally during a maintenance window; --scope is honoured.

Examples:

  elsereno tristation --passive --file triton.pcapng
  elsereno tristation --passive --file triton.pcapng --json
  elsereno tristation --active --target sis.example:1502
  elsereno tristation --active --target sis.example:1502 --status`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case o.active == o.passive:
				return fail(core.ExitUsage, errors.New("pick exactly one of --active or --passive"))
			case o.passive:
				if o.file == "" {
					return fail(core.ExitUsage, errors.New("--passive needs --file capture.pcap[ng]"))
				}
				return runTriStationPassive(cmd, o.file, o.v.jsonOut)
			default:
				return o.v.runE(tristation.Name, func(cmd *cobra.Command, target string, timeout time.Duration, jsonOut bool) error {
					return runTriStationActive(cmd, target, timeout, jsonOut, o.status)
				})(cmd, args)
			}
		},
	}
	cmd.Flags().BoolVar(&o.active, "active", false, "fingerprint a live controller (CONNECT/DISCONNECT)")
	cmd.Flags().BoolVar(&o.passive, "passive", false, "decode a capture offline (no network)")
	cmd.Flags().StringVar(&o.file, "file", "", "pcap or pcapng capture for --passive")
	cmd.Flags().BoolVar(&o.status, "status", false, "with --active: also send one read-only Get CP status")
	o.v.register(cmd, "host:port of the controller for --active (e.g. sis:1502)", 10*time.Second, "overall timeout for --active")
	return cmd
}

func runTriStationPassive(cmd *cobra.Command, path string, jsonOut bool) error {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied capture path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ds, err := pcapfile.ReadUDP(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	r := tristation.Analyse(ds)
	if jsonOut {
		return emitS7JSON(cmd, r)
	}
	cmd.Printf("UDP datagrams: %d, TriStation frames: %d, undecodable on 1502: %d\n", r.Datagrams, r.TriStation, r.BadFrames)
	for _, c := range r.Controllers {
		cmd.Printf("Controller: %s\n", c)
	}
	names := make([]string, 0, len(r.Commands))
	for name := range r.Commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cmd.Printf("  %-28s %d\n", name, r.Commands[name])
	}
	for _, s := range r.Statuses {
		printCPStatus(cmd, s.Controller, s.Status)
	}
	if len(r.Changes) > 0 {
		cmd.Printf("[!] %d command(s) that change the safety program or run state:\n", len(r.Changes))
		for _, e := range r.Changes {
			cmd.Printf("  %s  %s -> %s  %s\n", e.Time.UTC().Format(time.RFC3339), e.Src, e.Dst, e.Name)
		}
	}
	printTriStationRefs(cmd)
	return nil
}

func runTriStationActive(cmd *cobra.Command, target string, timeout time.Duration, jsonOut, status bool) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	p := tristation.Default()
	s, err := p.Open(ctx, target)
	if err != nil {
		return err
	}
	defer s.Close()
	out := map[string]any{"target": target, "tristation": true}
	if status {
		st, err := s.Status()
		if err != nil {
			return fmt.Errorf("get CP status: %w", err)
		}
		st.Project = render.SafeBytes([]byte(st.Project))
		out["status"] = st
		if !jsonOut {
			cmd.Printf("TriStation: CONNECT REPLY from %s\n", target)
			printCPStatus(cmd, target, st)
			printTriStationRefs(cmd)
			return nil
		}
	}
	if jsonOut {
		return emitS7JSON(cmd, out)
	}
	cmd.Printf("TriStation: CONNECT REPLY from %s (disconnected; add --status for the key switch)\n", target)
	printTriStationRefs(cmd)
	return nil
}

func printCPStatus(cmd *cobra.Command, controller string, st wire.CPStatus) {
	cmd.Printf("CP status from %s: key %s, %s, project %q v%d.%d (downloaded %s)\n",
		controller, st.KeyName, st.RunName, render.SafeBytes([]byte(st.Project)),
		st.ProjectMajor, st.ProjectMinor, time.Unix(int64(st.ProjectTimestamp), 0).UTC().Format(time.RFC3339))
	if wire.KeyAllowsChanges(st.KeyState) {
		cmd.Println("[!] key switch in PROGRAM or REMOTE: the safety program can be changed over the network")
	}
}

func printTriStationRefs(cmd *cobra.Command) {
	for _, r := range standards.ForProtocol(tristation.Name) {
		cmd.Printf("  ref: %s %s %s\n", r.Standard, r.Table, r.Vuln)
	}
}
