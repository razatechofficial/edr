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
	c.trayDetail = fyne.NewMenuItem("Sensor · Stream", nil)
	c.trayDetail.Disabled = true
	c.trayRes = fyne.NewMenuItem("Resources —", nil)
	c.trayRes.Disabled = true
	open := fyne.NewMenuItem("Open", func() {
		c.showPopover()
	})
	quit := fyne.NewMenuItem("Quit", func() { c.app.Quit() })
	c.trayMenu = fyne.NewMenu(productName,
		open,
		fyne.NewMenuItemSeparator(),
		c.trayStatus,
		c.trayDetail,
		c.trayRes,
		fyne.NewMenuItemSeparator(),
		quit,
	)
	desk.SetSystemTrayMenu(c.trayMenu)
	desk.SetSystemTrayIcon(edrIcon())
}

func (c *console) refreshTray(st operatorStatus, res resourceSnapshot) {
	if c.trayMenu == nil {
		return
	}
	_, lamps := decorateHealth(st)
	c.trayStatus.Label = lamps.Title
	c.trayDetail.Label = fmt.Sprintf("Sensor %s · Stream %s", lamps.Sensor, lamps.Stream)
	if lamps.Banner != "" {
		c.trayDetail.Label = lamps.Banner
	}
	c.trayRes.Label = fmt.Sprintf("CPU %.1f%% agent · RAM %.0f MB", res.AgentCPU, res.AgentMemMB)
	c.trayMenu.Refresh()
}
