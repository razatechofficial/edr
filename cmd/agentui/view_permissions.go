package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/hostperm"
)

func (c *console) buildPermissions() fyne.CanvasObject {
	c.permHint = widget.NewLabel(permBody())
	c.permHint.Wrapping = fyne.TextWrapWord

	c.permLine = widget.NewLabel("Grant each required item, then Recheck.")
	c.permLine.Wrapping = fyne.TextWrapWord

	c.permBox = container.NewVBox()
	c.permFaultBox = container.NewVBox()

	c.grantBtn = widget.NewButton(openSettingsLabel(), c.onOpenSettings)
	c.grantBtn.Importance = widget.MediumImportance

	c.permRecheck = widget.NewButton("Recheck", func() {
		c.refreshPermissions(true)
	})
	c.permRecheck.Importance = widget.HighImportance

	c.permContinue = widget.NewButton("Continue", func() {
		if !hostperm.GrantsReady(hostperm.Evaluate()) {
			c.refreshPermissions(true)
			return
		}
		if c.last.Enrolled && serviceHealthy(c.last.Service) {
			c.returnToDash()
			return
		}
		c.show(uistate.Preflight)
	})
	c.permContinue.Importance = widget.HighImportance
	c.permContinue.Disable()

	header := pageHeader("Required access", colorWarn, "Grant OS access", "")
	header = container.NewVBox(header, c.permHint)
	foot := container.NewVBox(
		c.permLine,
		c.permFaultBox,
		container.NewGridWithColumns(2, c.grantBtn, c.permRecheck),
		c.permContinue,
	)
	c.permContent = wizardPage(header, card(c.permBox), foot)
	return c.permContent
}

func (c *console) onOpenSettings() {
	id := c.currentPermActionID()
	if id == "" {
		id = hostperm.IDFDA
		if isWindows() {
			id = hostperm.IDFirewall
		}
	}
	c.permOpened = true
	c.permRecheck.Enable()
	c.permLine.SetText("Opened System Settings. Grant access, then Recheck. Do not skip.")
	go func() {
		err := hostperm.OpenSettings(id)
		if err == nil {
			return
		}
		fyne.Do(func() {
			c.setPermGuide("Could not open System Settings. " + permGuide())
		})
	}()
}

func (c *console) currentPermActionID() string {
	for _, it := range c.permItems {
		if it.Status == hostperm.StatusAction || it.Status == hostperm.StatusFail {
			if it.Required || it.ID == hostperm.IDFDA {
				return it.ID
			}
		}
	}
	for _, it := range c.permItems {
		if it.Status == hostperm.StatusAction || it.Status == hostperm.StatusFail {
			return it.ID
		}
	}
	return ""
}

func (c *console) refreshPermissions(fromUser bool) {
	if fromUser {
		c.paintPermChecking()
		go func() {
			rep := hostperm.Evaluate()
			fyne.Do(func() {
				c.applyPermReport(rep, true)
			})
		}()
		return
	}
	c.applyPermReport(hostperm.Evaluate(), false)
}

func (c *console) paintPermChecking() {
	if c.permBox == nil {
		return
	}
	c.permLine.SetText("Checking…")
	c.permBox.Objects = nil
	items := c.permItems
	if len(items) == 0 {
		items = hostperm.GrantItems(hostperm.EvaluateQuick())
	}
	for _, it := range items {
		st := checkWait
		switch {
		case it.Status == hostperm.StatusOK || it.Status == hostperm.StatusNA:
			st = checkOK
		default:
			st = checkRun
		}
		c.permBox.Add(permRow(statusMark(st), it.Title, "", it.Status == hostperm.StatusOK || it.Status == hostperm.StatusNA))
	}
	c.permBox.Refresh()
}

func (c *console) applyPermReport(rep hostperm.Report, fromUser bool) {
	c.permItems = hostperm.GrantItems(rep)
	c.renderPermissions(rep)
	if hostperm.GrantsReady(rep) {
		c.setPermGuide("")
		return
	}
	if !fromUser {
		return
	}
	id := c.currentPermActionID()
	guide := permGuide()
	for _, it := range c.permItems {
		if it.ID == id && it.Guide != "" {
			guide = it.Guide
			break
		}
	}
	c.setPermGuide(guide)
}

func (c *console) renderPermissions(rep hostperm.Report) {
	if c.permBox == nil {
		return
	}
	c.permBox.Objects = nil
	items := hostperm.GrantItems(rep)
	optionalAction := false
	waiting := false
	for _, it := range items {
		st := checkWait
		switch it.Status {
		case hostperm.StatusOK, hostperm.StatusNA:
			st = checkOK
		case hostperm.StatusAction:
			st = checkRun
			waiting = true
			if !it.Required {
				optionalAction = true
			}
		case hostperm.StatusFail:
			st = checkFail
			waiting = true
		}
		badge := ""
		if it.Status == hostperm.StatusAction {
			badge = "Action required"
		}
		c.permBox.Add(permRow(statusMark(st), it.Title, badge, it.Status == hostperm.StatusOK || it.Status == hostperm.StatusNA))
	}
	c.permBox.Refresh()

	c.grantBtn.Enable()
	c.permRecheck.Enable()
	ready := hostperm.GrantsReady(rep)
	if ready {
		if optionalAction {
			c.permLine.SetText("Required access is granted. Optional items still need attention.")
			c.permHint.SetText(permBody())
		} else {
			c.permLine.SetText("All checks passed.")
			c.permHint.SetText("Required access is granted. Continue to the every-launch check.")
		}
		c.permContinue.Enable()
		c.permContinue.Show()
		if !waiting {
			c.grantBtn.Hide()
			c.permRecheck.Hide()
		}
		return
	}
	c.grantBtn.Show()
	c.permRecheck.Show()
	c.permContinue.Disable()
	id := c.currentPermActionID()
	line := "Grant each required item, then Recheck."
	for _, it := range items {
		if it.ID == id && it.Doing != "" {
			line = it.Doing
			break
		}
	}
	c.permLine.SetText(line)
}

func permRow(mark fyne.CanvasObject, title, badge string, titleMuted bool) fyne.CanvasObject {
	t := compactTitle(title, titleMuted)
	head := fyne.CanvasObject(t)
	if badge != "" {
		b := canvas.NewText(badge, colorWarn)
		b.TextSize = 11
		b.TextStyle = fyne.TextStyle{Bold: true}
		head = container.NewBorder(nil, nil, nil, b, t)
	}
	return container.NewPadded(container.NewBorder(nil, nil, mark, nil, head))
}

func (c *console) setPermGuide(text string) {
	if c.permFaultBox == nil {
		return
	}
	c.permFaultBox.Objects = nil
	if text != "" {
		c.permFaultBox.Add(guideWell(text))
	}
	c.permFaultBox.Refresh()
}

func (c *console) setPermFault(f uiFault) {
	if f.Title == "" {
		c.setPermGuide("")
		return
	}
	c.setPermGuide(f.Detail)
}

func permGuide() string {
	switch {
	case isDarwin():
		return "System Settings → Privacy & Security → Full Disk Access → enable edr. Then Recheck."
	case isWindows():
		return "Allow edr through Windows Defender Firewall if prompted. Then Recheck."
	default:
		return "Restore CAP_SYS_ADMIN / audit capabilities your packager set, then retry Start."
	}
}

func needsOSGrants() bool {
	return hostperm.NeedsGrants()
}
