package controlplane

import (
	"context"
	"net"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/razatechofficial/edr/pkg/protocol"
)

func TestGRPCServiceRegisterHeartbeatAlert(t *testing.T) {
	t.Parallel()

	reg, err := NewRegistry(RegistryConfig{DataDir: t.TempDir(), HeartbeatSec: 15})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewGRPCService(reg, zap.NewNop())

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	protocol.RegisterEDRServiceServer(s, svc)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := protocol.NewEDRServiceClient(conn)
	ctx := context.Background()

	regResp, err := client.Register(ctx, &protocol.RegistrationRequest{
		AgentId:  "agent-test-1",
		Hostname: "host1",
		Os:       "linux",
		Arch:     "amd64",
		Version:  "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !regResp.GetAccepted() {
		t.Fatalf("registration rejected: %s", regResp.GetMessage())
	}
	if regResp.GetHeartbeatSec() != 15 {
		t.Fatalf("heartbeat_sec = %d want 15", regResp.GetHeartbeatSec())
	}

	hbResp, err := client.Heartbeat(ctx, &protocol.HeartbeatRequest{
		AgentId: "agent-test-1",
		Status:  "running",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hbResp.GetAccepted() {
		t.Fatal("heartbeat rejected")
	}

	ack, err := client.ReportAlert(ctx, &protocol.Alert{
		AlertId:    "alert-1",
		EndpointId: "agent-test-1",
		RuleId:     "RULE-001",
		Title:      "test alert",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ack.GetAccepted() {
		t.Fatal("alert not accepted")
	}
	if reg.AgentCount() != 1 {
		t.Fatalf("agent count = %d want 1", reg.AgentCount())
	}
}
