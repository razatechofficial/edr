//go:build !windows

package main

import (
	"github.com/razatechofficial/edr/internal/config"
	"go.uber.org/zap"
)

func validateWindowsPPLBoot(cfg config.Config, logger *zap.Logger) error {
	return nil
}
