package main

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/hostperm"
)

type console struct {
	app fyne.App
	win fyne.Window
	pop fyne.Window

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
	enrollAdv      fyne.CanvasObject
	enrollAdvLink  *textLink
	enrollAdvOpen  bool

	identityBox   *fyne.Container
	identityHint  *widget.Label
	identityBar   *smoothBar
	identityCount *canvas.Text
	identityDoing *canvas.Text

	receipt         identityReceipt
	receiptBox      *fyne.Container
	receiptContinue *widget.Button

	permHint     *widget.Label
	permLine     *widget.Label
	permBox      *fyne.Container
	permFaultBox *fyne.Container
	permItems    []hostperm.Item
	permOpened   bool
	grantBtn     *widget.Button
	permRecheck  *widget.Button
	permContinue *widget.Button

	preflightBox      *fyne.Container
	preflightHint     *widget.Label
	preflightLine     *widget.Label
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
	setupProcess    *widget.Label
	setupWorking    *widget.Button
	setupRoot       *fyne.Container
	setupPhase      string
	cpuHist         []float64

	glow        *glowBG
	spark       *areaSpark
	ramBar      *ramBar
	heroFace    *heroFace
	healthTitle *canvas.Text
	sensorLamp  *canvas.Text
	streamLamp  *canvas.Text
	streamMark  *iconDot
	sensorLive  *liveDot
	bannerText  *canvas.Text
	bannerBg    *canvas.Rectangle
	bannerWrap  *fyne.Container
	cpuVal      *canvas.Text
	cpuUnit     *canvas.Text
	cpuHint     *canvas.Text
	ramVal      *canvas.Text
	ramUnit     *canvas.Text
	ramHint     *canvas.Text
	eventsVal   *canvas.Text
	threatsVal  *canvas.Text
	blocksVal   *canvas.Text
	uptimeVal   *canvas.Text
	agentLine   *canvas.Text

	dashAction   *widget.Button
	dashFaultBox *fyne.Container
	dashTail     *fyne.Container
	dashSheet    fyne.CanvasObject

	trayMenu *fyne.Menu

	screen     uistate.Screen
	busy       bool
	last       operatorStatus
	flyoutOpen bool
}

func runDashboard() error {
	release, exclusive := claimUIInstance(!flagTray)
	if !exclusive {
		return nil
	}
	defer release()

	a := app.NewWithID("com.razatech.edr.console")
	a.Settings().SetTheme(edrTheme{})
	a.SetIcon(edrIcon())

	w := a.NewWindow(productName)
	w.Resize(fyne.NewSize(wizardW, wizardH))
	w.SetFixedSize(true)

	c := &console{app: a, win: w}

	pop := a.NewWindow(productName)
	if drv, ok := a.Driver().(desktop.Driver); ok {
		pop = drv.CreateSplashWindow()
	}
	pop.SetIcon(edrIcon())
	pop.SetTitle(productName)
	pop.Resize(fyne.NewSize(popoverW, popoverH))
	pop.SetFixedSize(true)
	pop.SetCloseIntercept(func() {
		c.flyoutOpen = false
		pop.Hide()
	})
	c.pop = pop

	c.buildSetup()
	c.buildEnroll()
	c.buildIdentity()
	c.buildReceipt()
	c.buildPermissions()
	c.buildPreflight()
	c.buildDashboard()
	c.setupTray()
	registerAppActivate()
	setBecomeActive(func() {
		if c.screen != uistate.Dash {
			return
		}
		if c.win != nil && c.pop != nil {
			c.win.Hide()
		}
		if time.Since(lastTrayTap) < 500*time.Millisecond {
			return
		}
		if c.flyoutOpen {
			if c.pop != nil {
				c.pop.RequestFocus()
			}
			return
		}
		c.showDash()
	})
	setUIShow(func() {
		fyne.Do(func() { c.showDecoratedDash() })
	})

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
				if c.screen == uistate.Permissions {
					c.refreshPermissions(false)
				}
				c.refreshTray(st, res)
			})
		}
	}()

	a.Run()
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
		if flagTray {
			c.screen = uistate.Dash
			c.dismissToTray()
			return
		}
		c.showDecoratedDash()
		return
	}
	c.show(next)
}

func (c *console) show(id uistate.Screen) {
	c.screen = id
	if id == uistate.Dash {
		c.returnToDash()
		return
	}
	c.flyoutOpen = false
	if c.pop != nil {
		c.pop.Hide()
	}
	c.win.SetPadded(false)
	if id != uistate.Enroll {
		c.lockSize(wizardW, wizardHeight(id))
	}
	c.win.CenterOnScreen()
	switch id {
	case uistate.Setup:
		c.win.SetContent(c.setupContent)
	case uistate.Enroll:
		c.win.SetContent(c.enrollContent)
		c.fitEnroll()
		if c.token != nil {
			c.win.Canvas().Focus(c.token)
		}
	case uistate.Identity:
		c.win.SetContent(c.identityContent)
	case uistate.Receipt:
		c.win.SetContent(c.receiptContent)
	case uistate.Permissions:
		c.win.SetContent(c.permContent)
		c.refreshPermissions(false)
	case uistate.Preflight:
		c.win.SetContent(c.preflightContent)
		go c.runPreflight()
	}
	c.win.Show()
	bringWindowForward(c.win)
}

func (c *console) setBusy(on bool) {
	c.busy = on
	for _, b := range []*widget.Button{c.enrollBtn, c.startAgentBtn, c.grantBtn, c.receiptContinue, c.setupAccept, c.setupLaunch, c.setupDecline, c.setupClose, c.dashAction, c.permRecheck, c.permContinue} {
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
