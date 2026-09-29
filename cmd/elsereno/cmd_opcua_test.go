package main

import (
	"bytes"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/opcua"
)

func TestEmitOPCUAJSON_WalkKeys(t *testing.T) {
	t.Parallel()
	res := opcua.WriteableWalkResult{
		FoldersBrowsed: 2,
		VariablesRead:  3,
		Writeable: []opcua.WriteableNode{
			{NodeID: "ns=2;s=Setpoint", BrowseName: "Setpoint", UserAccessLevel: 0x03},
		},
	}
	res.IsOPCUA = true
	res.SessionOpened = true

	var buf bytes.Buffer
	cmd := newOPCUAProbeWriteCmd()
	cmd.SetOut(&buf)
	if err := emitOPCUAJSON(cmd, res); err != nil {
		t.Fatalf("emitOPCUAJSON: %v", err)
	}
	out := buf.String()
	for _, key := range []string{
		`"is_opcua"`, `"session_opened"`, `"folders_browsed"`,
		`"variables_read"`, `"writeable"`, `"node_id"`, `"user_access_level"`,
	} {
		if !strings.Contains(out, key) {
			t.Errorf("JSON missing key %s\n%s", key, out)
		}
	}
}

func TestOPCUAProbeAnonRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newOPCUAProbeAnonCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}

func TestOPCUAProbeWriteRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newOPCUAProbeWriteCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}
