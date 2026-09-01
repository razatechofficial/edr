package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/systray"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
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
	desk.SetSystemTrayIcon(edrTrayResource())
	open := fyne.NewMenuItem("Open", func() {
		c.reveal()
	})
	perms := fyne.NewMenuItem("Permissions", func() { c.show(uistate.Permissions) })
	updates := fyne.NewMenuItem("Check for updates", c.onCheckUpdates)
	uninstall := fyne.NewMenuItem("Uninstall…", c.onUninstall)
	quit := fyne.NewMenuItem("Quit", func() { c.app.Quit() })
	c.trayMenu = fyne.NewMenu(productName, open, fyne.NewMenuItemSeparator(), perms, updates, uninstall, fyne.NewMenuItemSeparator(), quit)
	desk.SetSystemTrayMenu(c.trayMenu)
	if c.pop != nil {
		desk.SetSystemTrayWindow(c.pop)
		systray.SetOnTapped(func() {
			fyne.Do(c.onTrayClick)
		})
	}
	systray.SetTooltip(productName)
	stayInMenuBar()
}

func (c *console) onTrayClick() {
	if c.flyoutOpen {
		c.flyoutOpen = false
		if c.pop != nil {
			c.pop.Hide()
		}
		return
	}
	c.last = mergeEnrollment(loadStatus(), c.last)
	if c.last.Enrolled && serviceHealthy(c.last.Service) {
		c.showDash()
		return
	}
	c.reveal()
}

func (c *console) refreshTray(_ operatorStatus, _ resourceSnapshot) {
}
