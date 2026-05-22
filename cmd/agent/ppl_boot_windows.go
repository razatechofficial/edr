//go:build windows

package main

import (
	"fmt"
	"os"

	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/selfprotect"
	"go.uber.org/zap"
)

func validateWindowsPPLBoot(cfg config.Config, logger *zap.Logger) error {
	exe, _ := os.Executable()
	posture := selfprotect.PPLPostureSnapshot(exe)
	logger.Info("windows PPL posture",
		zap.Uint32("protection_level", posture.ProtectionLevel),
		zap.String("level_name", posture.LevelName),
		zap.Bool("is_antimalware_ppl", posture.IsAntimalwarePPL),
		zap.Bool("authenticode_signed", posture.AuthenticodeSigned),
		zap.Bool("antimalware_eku", posture.AntimalwareEKU),
	)
	if posture.AuthenticodeSubject != "" {
		logger.Info("windows authenticode subject", zap.String("subject", posture.AuthenticodeSubject))
	}
	if !posture.IsAntimalwarePPL && cfg.Monitoring.WindowsServiceLaunchProtectedTier == "antimalware_light" {
		logger.Warn("AM-PPL tier configured but process is not running as antimalware PPL; service reinstall with MVI-signed binary required",
			zap.String("signing_prerequisite", posture.SigningNote),
		)
	}
	if err := selfprotect.ValidatePPLRequired(cfg.Monitoring.WindowsPPLRequired, posture); err != nil {
		return fmt.Errorf("windows PPL boot check: %w", err)
	}
	return nil
}
