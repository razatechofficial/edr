package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func runLinuxTUI() error {
	in := bufio.NewReader(os.Stdin)
	if flagSetup || !agentInstalled() {
		for {
			cont, err := linuxSetup(in)
			if err != nil {
				fmt.Println()
				fmt.Println(err.Error())
				if !linuxAskRetry(in) {
					return err
				}
				continue
			}
			if !cont {
				return nil
			}
			break
		}
	}
	st := loadStatus()
	if !st.Enrolled {
		for {
			err := linuxEnroll(in)
			if err == nil {
				break
			}
			fmt.Println()
			fmt.Println(err.Error())
			if !linuxAskRetry(in) {
				return err
			}
		}
		st = loadStatus()
	}
	if !serviceHealthy(st.Service) {
		for {
			err := linuxPreflight(in)
			if err == nil {
				break
			}
			fmt.Println()
			fmt.Println(err.Error())
			if !linuxAskRetry(in) {
				return err
			}
		}
		st = loadStatus()
	}
	linuxStatusLoop(st)
	return nil
}

func linuxAskRetry(in *bufio.Reader) bool {
	fmt.Print("Try again? [Y/n]: ")
	ans, _ := in.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	return ans != "n" && ans != "no"
}

func linuxSetup(in *bufio.Reader) (continueWizard bool, err error) {
	fmt.Println("EDR Agent — license agreement")
	fmt.Println()
	fmt.Println(eulaText)
	fmt.Println()
	fmt.Println("Installs for all users of this computer.")
	fmt.Print("Accept? [y/N]: ")
	ans, _ := in.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans != "y" && ans != "yes" {
		fmt.Println("Setup was cancelled. EDR Agent was not installed.")
		return false, nil
	}
	if !installerPresent() {
		return false, fmt.Errorf("edr-installer not found; deploy the rpm/deb or place edr-installer on PATH")
	}
	fmt.Println("Installing (package + systemd). No token on this step…")
	out, ierr := runInstallerPrivileged("install", "--no-start")
	if ierr != nil {
		f := classifyInstallError(out + "\n" + ierr.Error())
		return false, fmt.Errorf("%s: %s", f.Title, f.Detail)
	}
	fmt.Println("Files are installed. Next: enroll this device.")
	return true, nil
}

func linuxEnroll(in *bufio.Reader) error {
	fmt.Println()
	fmt.Println("First run — Enroll this device")
	fmt.Println(enrollBody())
	fmt.Print("Enrollment token: ")
	tok, _ := in.ReadString('\n')
	tok = strings.TrimSpace(tok)
	if tok == "" {
		f := faultTokenMissing()
		return fmt.Errorf("%s", f.Title)
	}
	fmt.Print("Management domain (blank = " + apexSaaS + "): ")
	apex, _ := in.ReadString('\n')
	apex = strings.TrimSpace(apex)
	if domainLooksInvalid(apex) {
		return fmt.Errorf("%s", faultDomainInvalid().Title)
	}
	host := enrollmentHostFromDomain(apex)
	fmt.Println("Securing device identity (private key never leaves this host)…")
	titles := identityTitles()
	xdrclient.ClearEnrollProgress(platform.DataDir())

	type enrollRes struct {
		out string
		err error
	}
	done := make(chan enrollRes, 1)
	go func() {
		out, err := runEdrctlPrivileged("enroll", "--force", "--host", host, "--token", tok)
		done <- enrollRes{out, err}
	}()

	active := -1
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var res enrollRes
wait:
	for {
		select {
		case res = <-done:
			break wait
		case <-tick.C:
			step := xdrclient.ReadEnrollProgress(platform.DataDir())
			idx := identityStepIndex(step)
			if idx > active && idx >= 0 && idx < len(titles) {
				active = idx
				fmt.Printf("  → %s\n", titles[active])
			}
		}
	}

	st := loadStatus()
	if !enrollLooksSuccessful(res.out, res.err, st) {
		msg := strings.TrimSpace(res.out)
		if msg == "" && res.err != nil {
			msg = res.err.Error()
		}
		if msg == "" {
			msg = "Enrollment did not return a device certificate."
		}
		f := classifyEnrollError(msg)
		return fmt.Errorf("%s\n%s\n%s", f.Title, f.Body, f.Detail)
	}
	r := receiptFromEnroll(res.out, st)
	fmt.Println()
	fmt.Println("Identity bound")
	fmt.Printf("  Device ID    %s\n", r.DeviceID)
	fmt.Printf("  Machine ID   %s\n", r.MachineID)
	fmt.Printf("  Issued by    %s\n", r.IssuedBy)
	fmt.Printf("  Valid until  %s\n", r.ValidUntil)
	fmt.Printf("  Stored in    %s\n", r.Storage)
	fmt.Println("  Keystore receipt · ingest host not shown")
	return nil
}

func linuxPreflight(in *bufio.Reader) error {
	fmt.Println()
	fmt.Println("Ready to start — each start re-checks cert, capabilities, service, spool.")
	items := newPreflightItems()
	st := loadStatus()
	allOK := true
	for i := range items {
		ok, detail := runOneCheck(items[i].ID, st)
		mark := "FAIL"
		if ok {
			mark = "OK"
		} else {
			allOK = false
		}
		fmt.Printf("  [%s] %s  %s\n", mark, items[i].Title, detail)
	}
	if !allOK {
		return fmt.Errorf("preflight failed; fix the items above and retry")
	}
	fmt.Print("Start EDR Agent? [Y/n]: ")
	ans, _ := in.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "n" || ans == "no" {
		return nil
	}
	out, err := runEdrctlPrivileged("start")
	st = loadStatus()
	if err != nil && !serviceHealthy(st.Service) {
		f := classifyStartError(out)
		return fmt.Errorf("%s: %s", f.Title, f.Detail)
	}
	fmt.Println("Sensor started.")
	return nil
}

func linuxStatusLoop(st operatorStatus) {
	fmt.Println()
	printLinuxStatus(st)
	fmt.Println("q quit   r refresh")
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "q", "quit":
			return
		case "r", "refresh", "":
			st = loadStatus()
			printLinuxStatus(st)
		}
	}
}

func printLinuxStatus(st operatorStatus) {
	res := sampleResources(st)
	_, lamps := decorateHealth(st)
	id := dash(st.AgentID)
	if len(id) > 12 {
		id = id[:12]
	}
	fmt.Printf("%s    %s\n", lamps.Title, id)
	fmt.Printf("sensor %s  ·  stream %s\n", lamps.Sensor, lamps.Stream)
	if lamps.Banner != "" {
		fmt.Printf("! %s\n", lamps.Banner)
	}
	fmt.Printf("EDR CPU  %.1f%%  (other %.0f%% · system %.0f%%)\n", res.AgentCPU, res.OtherCPU, res.SysCPU)
	v, u := formatAgentRAM(res.AgentMemMB)
	fmt.Printf("EDR RAM  %s %s  (%s)\n", v, u, ramBreakdown(res))
	fmt.Printf("%d events   %d threats   %d blocked\n", st.EventsProc, st.Detections, st.Blocks)
	rules := "Rules —"
	if st.RulesCount > 0 {
		rules = fmt.Sprintf("Rules %d", st.RulesCount)
	}
	fmt.Printf("%s · %s\n", dash(st.Uptime), rules)
}
