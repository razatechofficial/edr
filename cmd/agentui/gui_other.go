//go:build !windows && !darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func runGUI() error {
	if _, err := exec.LookPath("zenity"); err == nil {
		return runZenity()
	}
	fmt.Fprintln(os.Stderr, "No desktop GUI available; showing terminal dashboard.")
	cmd := exec.Command(edrctlPath(), "ui")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runZenity() error {
	for {
		status, _ := runEdrctl("ui")
		if status == "" {
			status = "EDR Agent"
		}
		out, err := exec.Command("zenity", "--list", "--title=EDR Agent",
			"--text="+status,
			"--column=Action",
			"Refresh status", "Enroll device", "Test connection", "Start agent", "Stop agent", "Quit",
		).CombinedOutput()
		if err != nil {
			return nil
		}
		choice := strings.TrimSpace(string(out))
		switch {
		case strings.Contains(choice, "Quit"):
			return nil
		case strings.Contains(choice, "Enroll"):
			tok, err := exec.Command("zenity", "--entry", "--title=EDR Agent", "--text=Enrollment token").CombinedOutput()
			if err != nil {
				continue
			}
			msg, e := runEdrctl("enroll", "--token", strings.TrimSpace(string(tok)))
			_ = exec.Command("zenity", "--info", "--title=Enroll", "--text="+msgOrErr(msg, e)).Run()
		case strings.Contains(choice, "Test"):
			msg, e := runEdrctl("test-connection")
			_ = exec.Command("zenity", "--info", "--title=Connection", "--text="+msgOrErr(msg, e)).Run()
		case strings.Contains(choice, "Start"):
			msg, e := runEdrctl("start")
			_ = exec.Command("zenity", "--info", "--title=Start", "--text="+msgOrErr(msg, e)).Run()
		case strings.Contains(choice, "Stop"):
			msg, e := runEdrctl("stop")
			_ = exec.Command("zenity", "--info", "--title=Stop", "--text="+msgOrErr(msg, e)).Run()
		}
	}
}

func msgOrErr(msg string, err error) string {
	if err != nil && msg == "" {
		return err.Error()
	}
	if msg == "" {
		return "ok"
	}
	return msg
}
