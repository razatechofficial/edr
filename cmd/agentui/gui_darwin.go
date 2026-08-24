//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func runGUI() error {
	for {
		status, _ := runEdrctl("ui")
		if status == "" {
			status = "EDR Agent — choose an action"
		}
		if len(status) > 900 {
			status = status[:900] + "\n…"
		}
		choice, err := osascriptChoice(status)
		if err != nil || choice == "" || choice == "Quit" || choice == "false" {
			return nil
		}
		switch choice {
		case "Refresh status":
			continue
		case "Enroll device":
			token, ok := osascriptToken()
			if !ok || strings.TrimSpace(token) == "" {
				continue
			}
			out, err := adminEdrctl("enroll", "--token", shellQuote(token))
			osascriptAlert("Enroll", out, err)
		case "Test connection":
			out, err := runEdrctl("test-connection")
			osascriptAlert("Connection test", out, err)
		case "Start agent":
			out, err := adminEdrctl("start")
			osascriptAlert("Start", out, err)
		case "Stop agent":
			out, err := adminEdrctl("stop")
			osascriptAlert("Stop", out, err)
		case "Grant permissions":
			_ = exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles").Start()
			_ = exec.Command("/Library/Application Support/EDR/first-run-permissions.sh", "--force").Start()
		}
	}
}

func osascriptChoice(prompt string) (string, error) {
	script := fmt.Sprintf(`
try
	set c to choose from list {"Refresh status", "Enroll device", "Test connection", "Start agent", "Stop agent", "Grant permissions", "Quit"} with title "EDR Agent" with prompt %s default items {"Refresh status"}
	if c is false then return "Quit"
	return item 1 of c
on error
	return "Quit"
end try
`, applescriptString(prompt))
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func osascriptToken() (string, bool) {
	script := `
try
	set r to display dialog "Paste the enrollment token from the XDR console." default answer "" with title "EDR Agent — Enroll" buttons {"Cancel", "Enroll"} default button "Enroll"
	if button returned of r is "Enroll" then return text returned of r
	return ""
on error
	return ""
end try
`
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return "", false
	}
	t := strings.TrimSpace(string(out))
	return t, t != ""
}

func osascriptAlert(title, body string, runErr error) {
	msg := body
	if runErr != nil && msg == "" {
		msg = runErr.Error()
	}
	if msg == "" {
		msg = "ok"
	}
	_ = exec.Command("osascript", "-e", fmt.Sprintf(`display dialog %s with title %s buttons {"OK"} default button "OK"`, applescriptString(msg), applescriptString(title))).Run()
}

func adminEdrctl(args ...string) (string, error) {
	cmd := edrctlPath() + " " + strings.Join(args, " ")
	script := fmt.Sprintf(`do shell script %s with administrator privileges`, applescriptString(cmd))
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func applescriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func shellQuote(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
}

func init() {
	_ = os.Setenv("PATH", "/usr/local/bin:/usr/bin:/bin:"+os.Getenv("PATH"))
}
