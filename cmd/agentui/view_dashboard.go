package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildDashboard() fyne.CanvasObject {
	c.healthDot = canvas.NewCircle(colorOK)
	c.healthDot.StrokeWidth = 0
	c.healthTitle = canvas.NewText("SECURE", colorOK)
	c.healthTitle.TextSize = 28
	c.healthTitle.TextStyle = fyne.TextStyle{Bold: true}
	c.healthTitle.Alignment = fyne.TextAlignCenter
	c.healthSub = widget.NewLabel("SYSTEM PROTECTED")
	c.healthSub.Alignment = fyne.TextAlignCenter

	c.monitorCheck = widget.NewCheck("Active monitoring", c.onMonitorToggle)
	c.streamHint = widget.NewLabel("Real-time threat detection is active.")
	c.streamHint.Wrapping = fyne.TextWrapWord

	c.threatsVal = canvas.NewText("0", colorPink)
	c.threatsVal.TextSize = 28
	c.threatsVal.TextStyle = fyne.TextStyle{Bold: true}
	c.handledVal = canvas.NewText("0", colorOK)
	c.handledVal.TextSize = 28
	c.handledVal.TextStyle = fyne.TextStyle{Bold: true}

	c.cpuBar = widget.NewProgressBar()
	c.cpuSys = widget.NewLabel("System  —")
	c.cpuAgent = widget.NewLabel("Agent   —")
	c.ramBar = widget.NewProgressBar()
	c.ramSys = widget.NewLabel("System  —")
	c.ramAgent = widget.NewLabel("Agent   —")
	c.uptimeVal = widget.NewLabel("Uptime —")
	c.agentLine = widget.NewLabel("Agent ID —")
	c.agentLine.Wrapping = fyne.TextWrapWord
	c.uptimeVal.Wrapping = fyne.TextWrapWord

	statusCard := card(container.NewVBox(
		caption("SYSTEM STATUS"),
		container.NewCenter(container.NewHBox(
			container.NewGridWrap(fyne.NewSize(12, 12), c.healthDot),
			c.healthTitle,
		)),
		c.healthSub,
		c.uptimeVal,
		c.agentLine,
	))

	metrics := container.NewGridWithColumns(2,
		accentCard(colorPink, container.NewVBox(caption("THREATS"), c.threatsVal)),
		accentCard(colorOK, container.NewVBox(caption("HANDLED"), c.handledVal)),
	)
	cpuCard := card(container.NewVBox(
		caption("CPU  SYSTEM vs AGENT"),
		c.cpuSys,
		c.cpuAgent,
		c.cpuBar,
	))
	ramCard := card(container.NewVBox(
		caption("MEMORY  SYSTEM vs AGENT"),
		c.ramSys,
		c.ramAgent,
		c.ramBar,
	))
	monitor := card(container.NewBorder(nil, nil, nil, c.monitorCheck, container.NewVBox(
		widget.NewLabelWithStyle("Active monitoring", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		c.streamHint,
	)))

	body := container.NewVBox(
		c.chrome(container.NewHBox(c.settingsButton())),
		stepLabel(3, 3, "Protection"),
		statusCard,
		metrics,
		cpuCard,
		ramCard,
		monitor,
	)
	c.dashContent = container.NewPadded(container.NewVScroll(body))
	return c.dashContent
}

func (c *console) applyDashboard(st operatorStatus, res resourceSnapshot) {
	k := uistate.ClassifyHealth(st.Enrolled, serviceHealthy(st.Service), st.ControlAPI == "ok", st.Isolated)
	title, sub := uistate.HealthCopy(k)
	col := colorMuted
	switch k {
	case uistate.Secure:
		col = colorOK
	case uistate.Contained:
		col = colorDanger
	case uistate.Degraded:
		col = colorWarn
	}
	c.healthTitle.Text = title
	c.healthTitle.Color = col
	c.healthTitle.Refresh()
	c.healthDot.FillColor = col
	c.healthDot.Refresh()
	c.healthSub.SetText(sub)
	c.threatsVal.Text = fmt.Sprintf("%d", st.Detections)
	c.threatsVal.Refresh()
	c.handledVal.Text = fmt.Sprintf("%d", st.EventsProc)
	c.handledVal.Refresh()
	c.uptimeVal.SetText("Uptime  " + dash(st.Uptime))
	id := dash(st.AgentID)
	if st.Ingest != "" {
		id += "\nIngest  " + st.Ingest
	}
	c.agentLine.SetText("Agent   " + id)

	c.cpuSys.SetText(fmt.Sprintf("System  %.0f%%", res.SysCPU))
	c.cpuAgent.SetText(fmt.Sprintf("Agent   %.1f%%", res.AgentCPU))
	c.cpuBar.SetValue(clamp01(res.SysCPU / 100))
	if res.SysMemTot > 0 {
		c.ramSys.SetText(fmt.Sprintf("System  %s / %s", formatBytesGB(res.SysMemUsed), formatBytesGB(res.SysMemTot)))
		c.ramBar.SetValue(float64(res.SysMemUsed) / float64(res.SysMemTot))
	} else {
		c.ramSys.SetText("System  —")
	}
	c.ramAgent.SetText(fmt.Sprintf("Agent   %.0f MB", res.AgentMemMB))

	on := serviceHealthy(st.Service)
	c.ignoreMonitor = true
	c.monitorCheck.SetChecked(on)
	c.ignoreMonitor = false
	if on {
		c.streamHint.SetText("Real-time threat detection is active.")
	} else {
		c.streamHint.SetText("Start streaming to send telemetry to XDR.")
	}
}

func (c *console) onMonitorToggle(on bool) {
	if c.ignoreMonitor || c.busy {
		c.ignoreMonitor = false
		return
	}
	c.setBusy(true)
	go func() {
		var out string
		var err error
		if on {
			out, err = runEdrctlPrivileged("start")
		} else {
			out, err = runEdrctlPrivileged("stop")
		}
		st := loadStatus()
		res := sampleResources(st)
		fyne.Do(func() {
			c.setBusy(false)
			c.last = st
			c.applyDashboard(st, res)
			c.refreshTray(st, res)
			if err != nil {
				c.streamHint.SetText(clipErr(out))
			}
		})
	}()
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
