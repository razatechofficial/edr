package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/razatechofficial/edr/internal/pidfile"
	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/schema"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: edrctl <alerts|kill|stop>")
	}
	switch os.Args[1] {
	case "alerts":
		alertFile := "./alerts/alerts.jsonl"
		if len(os.Args) >= 3 {
			alertFile = os.Args[2]
		}
		if err := printAlerts(alertFile); err != nil {
			log.Fatal(err)
		}
	case "kill":
		if len(os.Args) < 3 {
			log.Fatal("usage: edrctl kill <pid>")
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatalf("invalid pid: %v", err)
		}
		r := response.NewResponder(true, []string{"systemd", "launchd", "wininit.exe"})
		res := r.Execute(schema.ResponseCommand{
			SchemaVersion: schema.SchemaVersionV1,
			Action:        schema.ResponseKillProcess,
			ProcessPID:    pid,
			ProcessName:   "manual",
		})
		fmt.Printf("kill result: success=%t message=%s\n", res.Success, res.Message)
	case "stop":
		pidPath := "./alerts/agent.pid"
		if len(os.Args) >= 3 {
			pidPath = os.Args[2]
		}
		pid, err := pidfile.ReadPID(pidPath)
		if err != nil {
			log.Fatalf("read pidfile: %v", err)
		}
		p, err := os.FindProcess(pid)
		if err != nil {
			log.Fatalf("find process: %v", err)
		}
		var stopErr error
		if runtime.GOOS == "windows" {
			stopErr = p.Kill()
		} else {
			stopErr = p.Signal(syscall.SIGTERM)
		}
		if stopErr != nil {
			log.Fatalf("stop: %v", stopErr)
		}
		if runtime.GOOS == "windows" {
			fmt.Printf("terminated pid %d (from %s)\n", pid, pidPath)
		} else {
			fmt.Printf("sent SIGTERM to pid %d (from %s)\n", pid, pidPath)
		}
	default:
		log.Fatalf("unknown command: %s", os.Args[1])
	}
}

func printAlerts(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var al schema.Alert
		if err := json.Unmarshal(sc.Bytes(), &al); err != nil {
			fmt.Printf("invalid row: %s\n", sc.Text())
			continue
		}
		fmt.Printf("%s %-8s %-10s %s\n", al.Timestamp.Format("2006-01-02T15:04:05Z"), al.Severity, al.RuleID, al.Title)
	}
	return sc.Err()
}
