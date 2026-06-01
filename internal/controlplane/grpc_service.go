package controlplane

import (
	"context"
	"io"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/razatechofficial/edr/pkg/protocol"
)

// GRPCService implements the agent-facing EDR gRPC API.
type GRPCService struct {
	protocol.UnimplementedEDRServiceServer

	registry *Registry
	policy   *PolicyStore
	logger   *zap.Logger
}

// NewGRPCService builds a gRPC service backed by registry state.
func NewGRPCService(registry *Registry, policy *PolicyStore, logger *zap.Logger) *GRPCService {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &GRPCService{registry: registry, policy: policy, logger: logger}
}

func (s *GRPCService) Register(ctx context.Context, req *protocol.RegistrationRequest) (*protocol.RegistrationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "registration request required")
	}
	resp := s.registry.Register(req)
	if !resp.GetAccepted() {
		return resp, nil
	}
	s.logger.Info("agent registered",
		zap.String("agent_id", resp.GetAgentId()),
		zap.String("hostname", req.GetHostname()),
		zap.String("os", req.GetOs()),
	)
	return resp, nil
}

func (s *GRPCService) Heartbeat(ctx context.Context, req *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	if req == nil || req.GetAgentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id required")
	}
	return s.registry.Heartbeat(req), nil
}

func (s *GRPCService) GetPolicy(ctx context.Context, req *protocol.PolicyRequest) (*protocol.PolicyResponse, error) {
	if req == nil || req.GetAgentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id required")
	}
	if s.policy != nil {
		return s.policy.GetPolicy(req.GetCurrentPolicyHash()), nil
	}
	return &protocol.PolicyResponse{
		PolicyHash: "local-default",
		Changed:    false,
	}, nil
}

func (s *GRPCService) ReportAlert(ctx context.Context, alert *protocol.Alert) (*protocol.AlertAck, error) {
	if alert == nil {
		return nil, status.Error(codes.InvalidArgument, "alert required")
	}
	if err := s.registry.RecordAlert(alert); err != nil {
		return nil, status.Errorf(codes.Internal, "record alert: %v", err)
	}
	s.logger.Info("alert ingested",
		zap.String("alert_id", alert.GetAlertId()),
		zap.String("agent_id", alert.GetEndpointId()),
		zap.String("rule_id", alert.GetRuleId()),
	)
	return &protocol.AlertAck{
		Accepted: true,
		AlertId:  alert.GetAlertId(),
		Message:  "accepted",
	}, nil
}

func (s *GRPCService) StreamEvents(stream protocol.EDRService_StreamEventsServer) error {
	ctx := stream.Context()
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if batch == nil {
			continue
		}
		s.logger.Debug("event batch received",
			zap.String("agent_id", batch.GetAgentId()),
			zap.Int32("sequence", batch.GetSequence()),
			zap.Int("process_events", len(batch.GetProcessEvents())),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (s *GRPCService) UploadForensics(stream protocol.EDRService_UploadForensicsServer) error {
	for {
		chunk, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&protocol.UploadResult{Success: true})
		}
		if err != nil {
			return err
		}
		if chunk == nil {
			continue
		}
	}
}
