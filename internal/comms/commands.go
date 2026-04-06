package comms

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CommandType identifies the requested server-initiated operation.
type CommandType string

const (
	CmdScanFile        CommandType = "scan_file"
	CmdIsolateHost     CommandType = "isolate_host"
	CmdCollectForensics CommandType = "collect_forensics"
	CmdUpdateRules     CommandType = "update_rules"
	CmdUpdateConfig    CommandType = "update_config"
	CmdRestartAgent    CommandType = "restart_agent"
)

// Command represents a server-initiated action to be executed on the agent.
type Command struct {
	ID        string            `json:"id"`
	Type      CommandType       `json:"type"`
	Params    map[string]string `json:"params,omitempty"`
	IssuedBy  string            `json:"issued_by"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at,omitempty"`
}

// CommandResult carries the outcome of a Command execution.
type CommandResult struct {
	CommandID   string    `json:"command_id"`
	CommandType CommandType `json:"command_type"`
	Success     bool      `json:"success"`
	Message     string    `json:"message,omitempty"`
	Data        []byte    `json:"data,omitempty"`
	CompletedAt time.Time `json:"completed_at"`
}

// CommandExecutor is implemented by subsystems that can execute a specific
// command type (file scanner, response engine, updater, etc.).
type CommandExecutor interface {
	Execute(ctx context.Context, cmd *Command) (*CommandResult, error)
}

// CommandHandler dispatches incoming commands to registered executors.
type CommandHandler struct {
	mu        sync.RWMutex
	executors map[CommandType]CommandExecutor
	logger    *zap.Logger
}

// NewCommandHandler creates a CommandHandler with no registered executors.
func NewCommandHandler(logger *zap.Logger) *CommandHandler {
	return &CommandHandler{
		executors: make(map[CommandType]CommandExecutor),
		logger:    logger,
	}
}

// Register adds an executor for the given command type.
func (ch *CommandHandler) Register(cmdType CommandType, executor CommandExecutor) {
	ch.mu.Lock()
	ch.executors[cmdType] = executor
	ch.mu.Unlock()
}

// HandleCommand validates and dispatches a command to its executor.
func (ch *CommandHandler) HandleCommand(cmd *Command) (*CommandResult, error) {
	if cmd == nil {
		return nil, fmt.Errorf("command_handler: nil command")
	}

	if !cmd.ExpiresAt.IsZero() && time.Now().After(cmd.ExpiresAt) {
		return &CommandResult{
			CommandID:   cmd.ID,
			CommandType: cmd.Type,
			Success:     false,
			Message:     "command expired",
			CompletedAt: time.Now().UTC(),
		}, nil
	}

	ch.mu.RLock()
	executor, ok := ch.executors[cmd.Type]
	ch.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("command_handler: no executor for %s", cmd.Type)
	}

	ch.logger.Info("executing command",
		zap.String("id", cmd.ID),
		zap.String("type", string(cmd.Type)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := executor.Execute(ctx, cmd)
	if err != nil {
		return &CommandResult{
			CommandID:   cmd.ID,
			CommandType: cmd.Type,
			Success:     false,
			Message:     err.Error(),
			CompletedAt: time.Now().UTC(),
		}, nil
	}

	result.CommandID = cmd.ID
	result.CommandType = cmd.Type
	result.CompletedAt = time.Now().UTC()

	ch.logger.Info("command completed",
		zap.String("id", cmd.ID),
		zap.Bool("success", result.Success),
	)
	return result, nil
}
