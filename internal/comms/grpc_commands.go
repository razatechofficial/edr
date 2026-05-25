package comms

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/pkg/protocol"
)

// ResponseExecutor executes a single response operation.
type ResponseExecutor interface {
	Execute(ctx context.Context, op response.OpKey, params map[string]interface{}) (*response.StepResult, error)
}

// ExecuteProtoCommand maps a control-plane command to the response engine.
func ExecuteProtoCommand(ctx context.Context, eng ResponseExecutor, cmd *protocol.Command, logger *zap.Logger) error {
	if cmd == nil {
		return fmt.Errorf("grpc_commands: nil command")
	}
	if eng == nil {
		return fmt.Errorf("grpc_commands: response engine unavailable")
	}
	if cmd.GetExpiresAt() != nil && time.Now().After(cmd.GetExpiresAt().AsTime()) {
		return fmt.Errorf("grpc_commands: command %s expired", cmd.GetCommandId())
	}

	op, params, err := protoCommandToOp(cmd)
	if err != nil {
		return err
	}
	if logger != nil {
		logger.Info("executing control-plane command",
			zap.String("command_id", cmd.GetCommandId()),
			zap.String("action", string(op)),
		)
	}
	result, err := eng.Execute(ctx, op, params)
	if err != nil {
		return err
	}
	if result != nil && !result.Success {
		return fmt.Errorf("grpc_commands: %s", result.Message)
	}
	return nil
}

func protoCommandToOp(cmd *protocol.Command) (response.OpKey, map[string]interface{}, error) {
	params := map[string]interface{}{}
	switch cmd.GetAction() {
	case protocol.ResponseAction_RESPONSE_ACTION_KILL_PROCESS:
		params["pid"] = int(cmd.GetProcessPid())
		params["process_name"] = cmd.GetProcessName()
		params["mode"] = "kill"
		return response.OpKillProcess, params, nil
	case protocol.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE:
		params["path"] = cmd.GetFilePath()
		return response.OpQuarantineFile, params, nil
	case protocol.ResponseAction_RESPONSE_ACTION_HOST_ISOLATE:
		return response.OpNetworkIsolate, params, nil
	case protocol.ResponseAction_RESPONSE_ACTION_HOST_RELEASE:
		return response.OpNetworkRelease, params, nil
	case protocol.ResponseAction_RESPONSE_ACTION_BLOCK_HASH:
		params["hash"] = cmd.GetHashValue()
		return response.OpBlockHash, params, nil
	case protocol.ResponseAction_RESPONSE_ACTION_COLLECT_FORENSIC:
		params["path"] = cmd.GetFilePath()
		return response.OpCollectForensics, params, nil
	case protocol.ResponseAction_RESPONSE_ACTION_TAKE_SNAPSHOT:
		return response.OpSnapshot, params, nil
	case protocol.ResponseAction_RESPONSE_ACTION_UPDATE_RULES,
		protocol.ResponseAction_RESPONSE_ACTION_UPDATE_CONFIG,
		protocol.ResponseAction_RESPONSE_ACTION_SCAN_FILE,
		protocol.ResponseAction_RESPONSE_ACTION_DISABLE_USER:
		return "", nil, fmt.Errorf("grpc_commands: action %s not implemented on agent", cmd.GetAction().String())
	default:
		return "", nil, fmt.Errorf("grpc_commands: unknown action %s", cmd.GetAction().String())
	}
}
