package comms

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/razatechofficial/edr/pkg/protocol"
)

type grpcHeartbeatTransport struct {
	client     *GRPCClient
	rulesFn    func() int
	onCommands func([]*protocol.Command)
}

func (t *grpcHeartbeatTransport) SendHeartbeat(ctx context.Context, data []byte) error {
	var payload HeartbeatPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	req := &protocol.HeartbeatRequest{
		AgentId:         payload.AgentID,
		Timestamp:       timestamppb.New(payload.Timestamp),
		Version:         payload.AgentVersion,
		Status:          "healthy",
		CpuPercent:      payload.CPUPercent,
		MemoryMb:        payload.MemoryMB,
		EventsProcessed: payload.EventsProcessed,
		AlertsGenerated: payload.AlertsGenerated,
		RulesLoaded:     int32(t.rulesFn()),
		UptimeSince:     timestamppb.New(time.Now().UTC().Add(-time.Duration(payload.Uptime) * time.Second)),
	}

	resp, err := t.client.Heartbeat(ctx, req)
	if err != nil {
		return err
	}
	if resp != nil && len(resp.GetPendingCommands()) > 0 && t.onCommands != nil {
		t.onCommands(resp.GetPendingCommands())
	}
	return nil
}
