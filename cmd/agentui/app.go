package main

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

type console struct {
	app fyne.App
	win fyne.Window

	enrollContent    fyne.CanvasObject
	identityContent  fyne.CanvasObject
	receiptContent   fyne.CanvasObject
	permContent      fyne.CanvasObject
	preflightContent fyne.CanvasObject
	dashContent      fyne.CanvasObject
	setupContent     fyne.CanvasObject

	domain         *widget.Entry
	token          *widget.Entry
	enrollBtn      *widget.Button
	enrollFaultBox *fyne.Container

	identityBox  *fyne.Container
	identityHint *widget.Label

	receipt         identityReceipt
	receiptBox      *fyne.Container
	receiptContinue *widget.Button

	permHint     *widget.Label
	permFaultBox *fyne.Container
	grantBtn     *widget.Button

	preflightBox      *fyne.Container
	preflightHint     *widget.Label
	preflightFaultBox *fyne.Container
	startAgentBtn     *widget.Button
	preflightItems    []preflightItem
	checksOK          bool

	setupBody       *fyne.Container
	setupHint       *widget.Label
	setupFaultBox   *fyne.Container
	setupSteps      *fyne.Container
	setupAccept     *widget.Button
	setupDecline    *widget.Button
	setupLaunch     *widget.Button
	setupLaunchHint *widget.Label
	setupClose      *widget.Button
	setupActions    *fyne.Container
	cpuSpark        *fyne.Container
	cpuHist         []float64

	healthTitle *canvas.Text
	healthSub   *widget.Label
	sensorLamp  *widget.Label
	streamLamp  *widget.Label
	cpuAgent    *widget.Label
	ramAgent    *widget.Label
	eventsVal   *widget.Label
	threatsVal  *widget.Label
	blocksVal   *widget.Label
	uptimeVal   *widget.Label
	agentLine   *widget.Label

	trayStatus *fyne.MenuItem
	trayDetail *fyne.MenuItem
	trayRes    *fyne.MenuItem
	trayMenu   *fyne.Menu

	screen uistate.Screen
	busy   bool
	last   operatorStatus
}

func runDashboard() error {
	a := app.NewWithID("com.razatech.edr.console")
	a.Settings().SetTheme(edrTheme{})
	a.SetIcon(edrIcon())

	w := a.NewWindow(productName)
	w.SetMaster()
	w.Resize(fyne.NewSize(wizardW, wizardH))
	w.SetFixedSize(true)
	w.CenterOnScreen()

	c := &console{app: a, win: w}
	c.buildSetup()
	c.buildEnroll()
	c.buildIdentity()
	c.buildReceipt()
	c.buildPermissions()
	c.buildPreflight()
	c.buildDashboard()
	c.setupTray()

	go func() {
		st := loadStatus()
		fyne.Do(func() {
			c.last = st
			c.routeInitial()
		})
	}()

	w.SetCloseIntercept(func() {
		if c.hasTray() {
			w.Hide()
			return
		}
		a.Quit()
	})

	go func() {
		t := time.NewTicker(8 * time.Second)
		defer t.Stop()
		for range t.C {
			st := loadStatus()
			res := sampleResources(st)
			fyne.Do(func() {
				c.last = st
				if c.screen == uistate.Dash {
					c.applyDashboard(st, res)
				}
				c.refreshTray(st, res)
			})
		}
	}()

	w.ShowAndRun()
	return nil
}

func (c *console) routeInitial() {
	installed := agentInstalled()
	if flagSetup && installed {
		c.show(uistate.Enroll)
		return
	}
	next := uistate.InitialScreen(installed, c.last.Enrolled, needsOSGrants(), serviceHealthy(c.last.Service))
	if next == uistate.Dash {
		c.showPopover()
		return
	}
	c.show(next)
}

func (c *console) show(id uistate.Screen) {
	c.screen = id
	if id == uistate.Dash {
		c.showPopover()
		return
	}
	c.lockSize(wizardW, wizardH)
	switch id {
	case uistate.Setup:
		c.win.SetContent(c.setupContent)
	case uistate.Enroll:
		c.win.SetContent(c.enrollContent)
		if c.token != nil {
			c.win.Canvas().Focus(c.token)
		}
	case uistate.Identity:
		c.win.SetContent(c.identityContent)
	case uistate.Receipt:
		c.win.SetContent(c.receiptContent)
	case uistate.Permissions:
		c.win.SetContent(c.permContent)
	case uistate.Preflight:
		c.win.SetContent(c.preflightContent)
		go c.runPreflight()
	}
	c.win.Show()
}

func (c *console) setBusy(on bool) {
	c.busy = on
	for _, b := range []*widget.Button{c.enrollBtn, c.startAgentBtn, c.grantBtn, c.receiptContinue, c.setupAccept, c.setupLaunch, c.setupDecline, c.setupClose} {
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
