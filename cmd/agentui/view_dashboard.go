package main

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildDashboard() fyne.CanvasObject {
	c.healthTitle = canvas.NewText("Protected", colorOK)
	c.healthTitle.TextSize = 24
	c.healthTitle.TextStyle = fyne.TextStyle{Bold: true}

	c.sensorLamp = widget.NewLabel("Sensor —")
	c.streamLamp = widget.NewLabel("Stream —")
	c.healthSub = widget.NewLabel("")
	c.healthSub.Wrapping = fyne.TextWrapWord

	c.cpuAgent = widget.NewLabel("—")
	c.ramAgent = widget.NewLabel("—")
	c.eventsVal = widget.NewLabel("—")
	c.threatsVal = widget.NewLabel("—")
	c.blocksVal = widget.NewLabel("—")
	c.uptimeVal = widget.NewLabel("—")
	c.agentLine = widget.NewLabel("")
	c.agentLine.TextStyle = fyne.TextStyle{Monospace: true}

	c.cpuSpark = container.NewHBox()
	c.cpuHist = make([]float64, 0, 12)

	status := card(container.NewVBox(
		c.healthTitle,
		container.NewHBox(c.sensorLamp, widget.NewLabel("·"), c.streamLamp),
		c.healthSub,
	))
	res := container.NewGridWithColumns(2,
		card(container.NewVBox(caption("Agent CPU"), c.cpuAgent, c.cpuSpark)),
		card(container.NewVBox(caption("Agent RAM"), c.ramAgent)),
	)
	counts := card(container.NewGridWithColumns(3,
		container.NewVBox(caption("Events"), c.eventsVal),
		container.NewVBox(caption("Threats"), c.threatsVal),
		container.NewVBox(caption("Blocked"), c.blocksVal),
	))
	foot := container.NewBorder(nil, nil, c.uptimeVal, c.agentLine, nil)

	body := container.NewVBox(status, res, counts, foot)
	c.dashContent = container.NewPadded(body)
	return c.dashContent
}

func (c *console) applyDashboard(st operatorStatus, res resourceSnapshot) {
	k, lamps := decorateHealth(st)

	col := colorMuted
	switch k {
	case uistate.Protected:
		col = colorOK
	case uistate.Contained:
		col = colorDanger
	case uistate.Degraded:
		col = colorWarn
	case uistate.Unprotected:
		col = colorDanger
	}
	c.healthTitle.Text = lamps.Title
	c.healthTitle.Color = col
	c.healthTitle.Refresh()
	c.sensorLamp.SetText("Sensor " + lamps.Sensor)
	c.streamLamp.SetText("Stream " + lamps.Stream)
	if lamps.Banner != "" {
		c.healthSub.SetText(lamps.Banner)
		c.healthSub.Show()
	} else {
		c.healthSub.SetText("")
		c.healthSub.Hide()
	}

	stopped := !serviceHealthy(st.Service)
	if stopped {
		c.cpuAgent.SetText("0.0%  ·  Sensor idle")
		c.ramAgent.SetText(fmt.Sprintf("%.0f MB", res.AgentMemMB))
		c.eventsVal.SetText("—")
		c.threatsVal.SetText("—")
		c.blocksVal.SetText("—")
		c.uptimeVal.SetText("—")
	} else {
		c.cpuAgent.SetText(fmt.Sprintf("%.1f%%  ·  System %.0f%%", res.AgentCPU, res.SysCPU))
		c.ramAgent.SetText(fmt.Sprintf("%.0f MB  ·  %s", res.AgentMemMB, formatBytesGB(res.SysMemTot)))
		c.eventsVal.SetText(fmt.Sprintf("%d", st.EventsProc))
		c.threatsVal.SetText(fmt.Sprintf("%d", st.Detections))
		c.blocksVal.SetText(fmt.Sprintf("%d", st.Blocks))
		rules := "Rules —"
		if st.RulesCount > 0 {
			rules = fmt.Sprintf("Rules %d", st.RulesCount)
		}
		c.uptimeVal.SetText(fmt.Sprintf("%s · %s", dash(st.Uptime), rules))
	}
	c.pushCPU(res.AgentCPU, stopped)
	id := dash(st.AgentID)
	if len(id) > 12 {
		id = id[:12]
	}
	c.agentLine.SetText(id)
}

func (c *console) pushCPU(pct float64, stopped bool) {
	if stopped {
		pct = 0
	}
	c.cpuHist = append(c.cpuHist, pct)
	if len(c.cpuHist) > 12 {
		c.cpuHist = c.cpuHist[len(c.cpuHist)-12:]
	}
	if c.cpuSpark == nil {
		return
	}
	c.cpuSpark.Objects = nil
	max := 1.0
	for _, v := range c.cpuHist {
		if v > max {
			max = v
		}
	}
	for _, v := range c.cpuHist {
		h := float32(6 + (v/max)*18)
		bar := canvas.NewRectangle(colorCyan)
		bar.CornerRadius = 1
		bar.SetMinSize(fyne.NewSize(7, h))
		c.cpuSpark.Add(bar)
	}
	c.cpuSpark.Refresh()
}

func (c *console) dismissToTray() {
	c.showPopover()
	if c.hasTray() {
		c.win.Hide()
	}
}

func (c *console) showPopover() {
	c.screen = uistate.Dash
	c.win.SetContent(c.dashContent)
	c.win.Resize(fyne.NewSize(336, 500))
	res := sampleResources(c.last)
	c.applyDashboard(c.last, res)
	c.refreshTray(c.last, res)
	c.win.Show()
}

func formatBytesMB(n int64) string {
	if n < 1024*1024 {
		return fmt.Sprintf("%d KB", n/1024)
	}
	return fmt.Sprintf("%.0f MB", float64(n)/(1024*1024))
}

func certExpiring(rfc3339 string) (bool, int) {
	if rfc3339 == "" {
		return false, 0
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return false, 0
	}
	d := int(time.Until(t).Hours() / 24)
	if d >= 0 && d <= 7 {
		return true, d
	}
	return false, d
}
