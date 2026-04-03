package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/razatechofficial/edr/internal/agent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := agent.NewDefault()
	if err != nil {
		log.Fatalf("agent init failed: %v", err)
	}

	if err := a.Run(ctx); err != nil {
		log.Fatalf("agent run failed: %v", err)
	}
}
