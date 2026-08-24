package main

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

type console struct {
	app fyne.App
	win fyne.Window

	enrollContent    fyne.CanvasObject
	preflightContent fyne.CanvasObject
	dashContent      fyne.CanvasObject

	host       *widget.Entry
	token      *widget.Entry
	enrollHint *widget.Label
	testBtn    *widget.Button
	enrollBtn  *widget.Button

	preflightBox   *fyne.Container
	preflightHint  *widget.Label
	startAgentBtn  *widget.Button
	grantBtn       *widget.Button
	preflightItems []preflightItem
	checksOK       bool

	healthDot     *canvas.Circle
	healthTitle   *canvas.Text
	healthSub     *widget.Label
	monitorCheck  *widget.Check
	ignoreMonitor bool
	threatsVal    *canvas.Text
	handledVal    *canvas.Text
	cpuSys        *widget.Label
	cpuAgent      *widget.Label
	cpuBar        *widget.ProgressBar
	ramSys        *widget.Label
	ramAgent      *widget.Label
	ramBar        *widget.ProgressBar
	uptimeVal     *widget.Label
	agentLine     *widget.Label
	streamHint    *widget.Label

	trayStatus *fyne.MenuItem
	trayDetail *fyne.MenuItem
	trayRes    *fyne.MenuItem
	trayMenu   *fyne.Menu

	screen screenID
	busy   bool
	last   operatorStatus
}

func runDashboard() error {
	a := app.NewWithID("com.razatech.edr.console")
	a.Settings().SetTheme(edrTheme{})
	a.SetIcon(edrIcon())

	w := a.NewWindow("EDR Agent")
	w.SetMaster()
	w.Resize(fyne.NewSize(440, 720))
	w.CenterOnScreen()
	w.SetFixedSize(true)

	c := &console{app: a, win: w}
	c.buildEnroll()
	c.buildPreflight()
	c.buildDashboard()
	c.setupTray()

	st := loadStatus()
	c.last = st
	need := needsFullDiskAccess() && !hasFullDiskAccess()
	c.show(initialScreen(st.Enrolled, need))

	w.SetCloseIntercept(func() {
		if c.screen == screenDash && c.hasTray() {
			w.Hide()
			return
		}
		a.Quit()
	})

	go func() {
		t := time.NewTicker(4 * time.Second)
		defer t.Stop()
		for range t.C {
			st := loadStatus()
			res := sampleResources(st)
			fyne.Do(func() {
				c.last = st
				if c.screen == screenDash {
					c.applyDashboard(st, res)
				}
				c.refreshTray(st, res)
			})
		}
	}()

	w.ShowAndRun()
	return nil
}

func (c *console) show(id screenID) {
	c.screen = id
	switch id {
	case screenEnroll:
		c.win.SetContent(c.enrollContent)
	case screenPreflight:
		c.win.SetContent(c.preflightContent)
		go c.runPreflight()
	case screenDash:
		c.win.SetContent(c.dashContent)
		res := sampleResources(c.last)
		c.applyDashboard(c.last, res)
		c.refreshTray(c.last, res)
	}
	c.win.Show()
}

func (c *console) setBusy(on bool) {
	c.busy = on
	for _, b := range []*widget.Button{c.testBtn, c.enrollBtn, c.startAgentBtn, c.grantBtn} {
		if b == nil {
			continue
		}
		if on {
			b.Disable()
		} else {
			b.Enable()
		}
	}
	if !on && c.startAgentBtn != nil && !c.checksOK {
		c.startAgentBtn.Disable()
	}
}

func (c *console) showSettings() {
	st := c.last
	body := fmt.Sprintf("Service: %s\nEnrollment: %v\nAgent ID: %s\nConfig: %s\nVersion: %s",
		dash(st.Service), st.Enrolled, dash(st.AgentID), dash(st.Config), dash(st.Version))
	dialog.ShowInformation("EDR Agent", body, c.win)
}
