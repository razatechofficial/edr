package main

import (
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/hostperm"
)

func (c *console) buildPreflight() fyne.CanvasObject {
	c.preflightBox = container.NewVBox()
	c.preflightHint = bodyText("Each start re-checks the certificate, OS access, service, and offline spool. Start edr when every line is green. The sensor can run if the cloud is unreachable.")
	c.preflightLine = processLine("Checking…")

	c.startAgentBtn = widget.NewButton("Start "+productName, c.onStartAgent)
	c.startAgentBtn.Importance = widget.HighImportance
	c.startAgentBtn.Disable()
	c.preflightFaultBox = container.NewVBox()

	recheck := widget.NewButton("Recheck", func() {
		go c.runPreflight()
	})
	recheck.Importance = widget.MediumImportance

	intro := inset(wizPad, wizPad, 8, wizPad, vstack(0,
		kicker("EVERY LAUNCH", colorAccent),
		gapH(4),
		heading("Ready to start"),
		gapH(8),
		c.preflightHint,
	))
	list := inset(4, wizPad, 4, wizPad, c.preflightBox)
	foot := checklistFooter(c.preflightLine, c.preflightFaultBox, recheck, c.startAgentBtn)
	c.preflightContent = firstRunFrame(checklistSheet(intro, list, foot))
	return c.preflightContent
}

func (c *console) renderPreflight() {
	c.preflightBox.Objects = nil
	allOK := len(c.preflightItems) > 0
	line := "Checking…"
	for _, it := range c.preflightItems {
		if it.State != checkOK {
			allOK = false
		}
		switch it.State {
		case checkFail:
			if it.Detail != "" {
				line = it.Detail
			}
		case checkRun:
			if it.Doing != "" {
				line = it.Doing
			} else {
				line = it.Title + "…"
			}
		}
		c.preflightBox.Add(checkRow(statusMark(it.State), it.Title, "", it.State))
	}
	c.preflightBox.Refresh()
	c.checksOK = allOK
	c.canStart = preflightCanStart(c.preflightItems)
	if c.canStart {
		c.startAgentBtn.Enable()
		if allOK {
			c.startAgentBtn.SetText("Start " + productName)
			line = "All checks passed. Start edr to load the sensor."
		} else {
			c.startAgentBtn.SetText("Register and start")
			line = "Allow Administrator, then Start."
		}
	} else {
		c.startAgentBtn.Disable()
	}
	if c.preflightLine != nil {
		c.preflightLine.SetText(line)
	}
	c.fitPreflight()
}

func (c *console) runPreflight() {
	items := newPreflightItems()
	fyne.DoAndWait(func() {
		c.preflightItems = items
		c.startAgentBtn.Disable()
		c.startAgentBtn.SetText("Working…")
		c.renderPreflight()
	})
	st := c.sessionStatus()
	const hold = 600 * time.Millisecond
	for i := range items {
		items[i].State = checkRun
		fyne.DoAndWait(func() {
			c.preflightItems = items
			c.renderPreflight()
		})
		started := time.Now()
		ok, detail := runOneCheck(items[i].ID, st)
		if ok {
			items[i].State = checkOK
		} else {
			items[i].State = checkFail
		}
		items[i].Detail = detail
		if d := hold - time.Since(started); d > 0 {
			time.Sleep(d)
		}
		fyne.DoAndWait(func() {
			c.preflightItems = items
			c.renderPreflight()
		})
	}
	fyne.Do(func() {
		c.startAgentBtn.SetText("Start " + productName)
	})
}

func (c *console) sessionStatus() operatorStatus {
	return mergeEnrollment(loadStatus(), c.last)
}

func (c *console) onStartAgent() {
	if c.busy || !c.canStart {
		return
	}
	c.startSensor()
}

func (c *console) startSensor() {
	c.setBusy(true)
	if c.preflightLine != nil {
		c.preflightLine.SetText("Starting the sensor…")
	}
	if c.preflightHint != nil {
		c.preflightHint.SetText("Each start re-checks the certificate, OS access, service, and offline spool. Start edr when every line is green. The sensor can run if the cloud is unreachable.")
	}
	if c.dashAction != nil {
		c.dashAction.SetText("Starting…")
	}
	c.setDashFault(uiFault{})
	if needsOSGrants() {
		c.setBusy(false)
		c.show(uistate.Permissions)
		return
	}
	go func() {
		if isWindows() {
			if !hostperm.SensorRegistered() {
				if err := runAgentInstallPrivileged(); err != nil && !serviceAlreadyPresentError(err.Error()) && !hostperm.SensorRegistered() {
					st := loadStatus()
					fyne.Do(func() {
						c.setBusy(false)
						f := classifyStartError(err.Error())
						c.setDashFault(f)
						c.setPreflightFault(f)
						if c.preflightLine != nil {
							c.preflightLine.SetText("Service registration did not finish.")
						}
						c.presentStartFault(f)
						go c.runPreflight()
						c.applyDashboard(st, sampleResources(st))
					})
					return
				}
			}
			// SCM can lag briefly after CreateService; wait before failing.
			deadline := time.Now().Add(8 * time.Second)
			for !hostperm.SensorRegistered() && time.Now().Before(deadline) {
				time.Sleep(400 * time.Millisecond)
			}
			if !hostperm.SensorRegistered() {
				st := loadStatus()
				fyne.Do(func() {
					c.setBusy(false)
					f := uiFault{
						Title:  "The sensor service is not registered",
						Body:   "EDRAgent was not created. Allow the Administrator prompt, or run edr-agent.exe --install from an elevated Command Prompt.",
						Detail: `"` + sensorBinaryPath() + `" --install`,
						Action: "Try again",
					}
					c.setDashFault(f)
					c.setPreflightFault(f)
					if c.preflightLine != nil {
						c.preflightLine.SetText("Service registration did not finish.")
					}
					c.presentStartFault(f)
					go c.runPreflight()
					c.applyDashboard(st, sampleResources(st))
				})
				return
			}
		}
		_, _ = runEdrctl("stage-identity")
		out, err := runEdrctlPrivileged("start")
		st := waitForService(8 * time.Second)
		fyne.Do(func() {
			c.setBusy(false)
			st = mergeEnrollment(st, c.last)
			c.last = st
			if err != nil || !serviceHealthy(st.Service) {
				f := classifyStartError(out)
				if f.Detail == "" && err != nil {
					f.Detail = err.Error()
				}
				if f.Title == "" {
					f.Title = "The sensor did not start"
					f.Body = "EDRAgent is registered but is not running. Allow Administrator if Windows asked, then Start again."
					f.Action = "OK"
				}
				c.setPreflightFault(uiFault{})
				c.setDashFault(f)
				if c.preflightLine != nil {
					c.preflightLine.SetText("Start did not finish.")
				}
				c.presentStartFault(f)
				c.applyDashboard(st, sampleResources(st))
				return
			}
			c.setPreflightFault(uiFault{})
			c.setDashFault(uiFault{})
			c.last = st
			c.dismissToTray()
		})
	}()
}

func (c *console) setPreflightFault(f uiFault) {
	if c.preflightFaultBox == nil {
		return
	}
	c.preflightFaultBox.Objects = nil
	if f.Title != "" {
		c.preflightFaultBox.Add(faultCard(f))
	}
	c.preflightFaultBox.Refresh()
	c.fitPreflight()
}

func (c *console) presentStartFault(f uiFault) {
	if strings.EqualFold(f.Action, "Grant access") || needsOSGrants() {
		c.show(uistate.Permissions)
		return
	}
	if c.screen == uistate.Preflight {
		c.fitPreflight()
		return
	}
	msg := widget.NewLabel(strings.TrimSpace(f.Body + "\n\n" + f.Detail))
	msg.Wrapping = fyne.TextWrapWord
	d := dialog.NewCustom(f.Title, firstNonEmpty(f.Action, "OK"), msg, c.win)
	d.Resize(fyne.NewSize(400, 220))
	d.Show()
}
