package comms

import (
	"testing"

	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/protocol"
)

func TestControlPlaneEnabled(t *testing.T) {
	t.Parallel()
	if controlPlaneEnabled(ControlPlaneConfig{ServerHost: "mgr", GRPCPort: 50051}) {
		// ok
	} else {
		t.Fatal("expected enabled")
	}
	if controlPlaneEnabled(ControlPlaneConfig{ServerHost: "mgr", GRPCPort: 50051, AirGapMode: true}) {
		t.Fatal("airgap should disable control plane")
	}
	if controlPlaneEnabled(ControlPlaneConfig{GRPCPort: 50051}) {
		t.Fatal("empty host should disable control plane")
	}
}

func TestNewGRPCClientRequiresAgentID(t *testing.T) {
	t.Parallel()
	if _, err := NewGRPCClient("mgr.example", 50051, "", nil, nil); err == nil {
		t.Fatal("expected agent_id error")
	}
}

func TestProtoCommandToOpKillProcess(t *testing.T) {
	t.Parallel()
	op, params, err := protoCommandToOp(&protocol.Command{
		Action:      protocol.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		ProcessPid:  4242,
		ProcessName: "evil.exe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if op != response.OpKillProcess {
		t.Fatalf("op = %q", op)
	}
	if params["pid"] != 4242 {
		t.Fatalf("pid = %v", params["pid"])
	}
}
