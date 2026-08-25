package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func (c *console) buildPreflight() fyne.CanvasObject {
	c.preflightBox = container.NewVBox()
	c.preflightHint = widget.NewLabel("Each start re-checks the certificate, OS access, service, and offline spool. Start when every line is green. The sensor can run if the cloud is unreachable.")
	c.preflightHint.Wrapping = fyne.TextWrapWord

	c.startAgentBtn = widget.NewButton("Start EDR Agent", c.onStartAgent)
	c.startAgentBtn.Importance = widget.HighImportance
	c.startAgentBtn.Disable()
	c.preflightFaultBox = container.NewVBox()

	recheck := widget.NewButton("Recheck", func() {
		go c.runPreflight()
	})
	recheck.Importance = widget.MediumImportance

	header := pageHeader("Every launch", colorAccent, "Ready to start", "")
	header = container.NewVBox(header, c.preflightHint)
	foot := container.NewVBox(c.preflightFaultBox, recheck, c.startAgentBtn)
	c.preflightContent = wizardPage(header, card(c.preflightBox), foot)
	return c.preflightContent
}

func (c *console) renderPreflight() {
	c.preflightBox.Objects = nil
	allOK := len(c.preflightItems) > 0
	for _, it := range c.preflightItems {
		if it.State != checkOK {
			allOK = false
		}
		c.preflightBox.Add(listRow(statusMark(it.State), it.Title, it.Detail, false))
	}
	c.preflightBox.Refresh()
	c.checksOK = allOK
	if allOK {
		c.startAgentBtn.Enable()
		c.preflightHint.SetText("All checks passed.")
	} else {
		c.startAgentBtn.Disable()
	}
}

func (c *console) runPreflight() {
	items := newPreflightItems()
	fyne.DoAndWait(func() {
		c.preflightItems = items
		c.startAgentBtn.Disable()
		c.renderPreflight()
	})
	st := loadStatus()
	for i := range items {
		items[i].State = checkRun
		fyne.DoAndWait(func() {
			c.preflightItems = items
			c.renderPreflight()
		})
		ok, detail := runOneCheck(items[i].ID, st)
		if ok {
			items[i].State = checkOK
		} else {
			items[i].State = checkFail
		}
		items[i].Detail = detail
		fyne.DoAndWait(func() {
			c.last = st
			c.preflightItems = items
			c.renderPreflight()
		})
	}
}

func (c *console) onStartAgent() {
	if c.busy || !c.checksOK {
		return
	}
	c.setBusy(true)
	c.preflightHint.SetText("Starting the sensor…")
	go func() {
		out, err := runEdrctlPrivileged("start")
		st := loadStatus()
		fyne.Do(func() {
			c.setBusy(false)
			c.last = st
			if err != nil && !serviceHealthy(st.Service) {
				f := classifyStartError(out)
				if f.Detail == "" && err != nil {
					f.Detail = err.Error()
				}
				c.setPreflightFault(f)
				c.preflightHint.SetText(f.Title)
				return
			}
			c.setPreflightFault(uiFault{})
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
}
