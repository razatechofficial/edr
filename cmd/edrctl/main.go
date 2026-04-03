package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/razatechofficial/edr/internal/response"
	"github.com/razatechofficial/edr/internal/schema"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: edrctl <alerts|kill>")
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
			FilePath:      "manual",
		})
		fmt.Printf("kill result: success=%t message=%s\n", res.Success, res.Message)
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
