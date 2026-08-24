package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

func (c *console) hasTray() bool {
	_, ok := c.app.(desktop.App)
	return ok
}

func (c *console) setupTray() {
	desk, ok := c.app.(desktop.App)
	if !ok {
		return
	}
	c.trayStatus = fyne.NewMenuItem("Status: …", nil)
	c.trayStatus.Disabled = true
	c.trayDetail = fyne.NewMenuItem("Threats —", nil)
	c.trayDetail.Disabled = true
	c.trayRes = fyne.NewMenuItem("Resources —", nil)
	c.trayRes.Disabled = true
	open := fyne.NewMenuItem("Open", func() {
		c.win.Show()
	})
	quit := fyne.NewMenuItem("Quit", func() { c.app.Quit() })
	c.trayMenu = fyne.NewMenu("EDR Agent",
		c.trayStatus,
		c.trayDetail,
		c.trayRes,
		fyne.NewMenuItemSeparator(),
		open,
		quit,
	)
	desk.SetSystemTrayMenu(c.trayMenu)
	desk.SetSystemTrayIcon(edrIcon())
}

func (c *console) refreshTray(st operatorStatus, res resourceSnapshot) {
	if c.trayMenu == nil {
		return
	}
	k := classifyHealth(st.Enrolled, serviceHealthy(st.Service), st.ControlAPI == "ok", st.Isolated)
	title, sub := healthCopy(k)
	c.trayStatus.Label = title + " · " + sub
	c.trayDetail.Label = fmt.Sprintf("Threats %d · Handled %d", st.Detections, st.EventsProc)
	c.trayRes.Label = fmt.Sprintf("CPU %.0f%% sys / %.1f%% agent · RAM %s", res.SysCPU, res.AgentCPU, formatBytesGB(res.SysMemUsed))
	c.trayMenu.Refresh()
}
