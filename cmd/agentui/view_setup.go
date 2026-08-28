package main

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/installprogress"
)

func (c *console) buildSetup() fyne.CanvasObject {
	c.setupHint = bodyText(bodyLicense)
	c.setupFaultBox = container.NewVBox()
	c.setupSteps = container.NewVBox()
	c.setupProcess = processLine("")
	c.setupProcess.Hide()

	c.setupAccept = widget.NewButton("Accept", c.onSetupAccept)
	c.setupAccept.Importance = widget.HighImportance
	c.setupDecline = widget.NewButton("Decline", c.onSetupDecline)
	c.setupActions = container.New(&equalRow{gap: 8}, c.setupDecline, c.setupAccept)

	c.setupWorking = widget.NewButton("Working…", nil)
	c.setupWorking.Importance = widget.MediumImportance
	c.setupWorking.Disable()
	c.setupWorking.Hide()

	c.setupLaunch = widget.NewButton("Launch "+productName, func() {
		c.show(uistate.Enroll)
	})
	c.setupLaunch.Importance = widget.HighImportance

	c.setupLaunchHint = widget.NewLabel(launchHint)
	c.setupLaunchHint.Wrapping = fyne.TextWrapWord
	c.setupLaunchHint.Alignment = fyne.TextAlignCenter
	c.setupLaunchHint.Importance = widget.LowImportance

	c.setupClose = widget.NewButton("Close", func() { c.app.Quit() })

	c.setupRoot = container.NewStack()
	c.setupContent = c.setupRoot
	c.paintSetupLicense()
	return c.setupContent
}

func (c *console) setSetupSheet(inner fyne.CanvasObject, h float32) {
	c.setupRoot.Objects = []fyne.CanvasObject{installerFrame(inner)}
	c.setupRoot.Refresh()
	if c.screen == uistate.Setup && c.win != nil {
		c.lockSize(wizardW, h)
		c.win.SetContent(c.setupContent)
	}
}

func (c *console) paintSetupLicense() {
	c.setupPhase = "license"
	eula := widget.NewLabel(eulaText)
	eula.Wrapping = fyne.TextWrapWord
	eula.Importance = widget.LowImportance
	eulaScroll := container.NewVScroll(eula)
	eulaScroll.SetMinSize(fyne.NewSize(0, wizEulaH))
	eulaWell := elevatedWell(8, inset(12, 12, 12, 12, eulaScroll))

	perTitle := canvas.NewText(perMachineTitle, colorText)
	perTitle.TextSize = 13
	perTitle.TextStyle = fyne.TextStyle{Bold: true}
	per := elevatedWell(8, inset(12, 12, 12, 12, vstack(4, perTitle, captionBlock(perMachineBody))))

	c.setupAccept.Show()
	c.setupDecline.Show()
	c.setupActions.Show()
	c.setupWorking.Hide()
	c.setupLaunch.Hide()
	c.setupLaunchHint.Hide()
	c.setupClose.Hide()
	c.setupProcess.Hide()

	inner := pad5(vstack(0,
		pageHeader(kickerLicense, colorMuted, titleLicense, bodyLicense),
		gapH(16),
		eulaWell,
		gapH(16),
		per,
		c.setupFaultBox,
		gapH(20),
		c.setupActions,
	))
	c.setSetupSheet(inner, 640)
}

func (c *console) paintSetupInstall() {
	c.setupPhase = "install"
	c.setupProcess.Show()
	c.setupWorking.Show()
	c.setupActions.Hide()
	c.setupLaunch.Hide()
	c.setupLaunchHint.Hide()
	c.setupClose.Hide()
	intro := inset(wizPad, wizPad, 8, wizPad, vstack(0,
		kicker(progressKicker, colorMuted),
		gapH(4),
		heading(progressTitle),
		gapH(8),
		bodyText(installProgressHint()),
	))
	foot := checklistFooter(c.setupProcess, c.setupWorking)
	inner := checklistSheet(intro, inset(8, wizPad, 8, wizPad, c.setupSteps), foot)
	c.setSetupSheet(inner, 520)
}

func (c *console) paintSetupFinish() {
	c.setupPhase = "finish"
	c.setupWorking.Hide()
	c.setupActions.Hide()
	c.setupClose.Hide()
	c.setupProcess.Hide()
	c.setupLaunch.Show()
	c.setupLaunchHint.Show()
	kick := kicker(kickerSetup, colorMuted)
	kick.Alignment = fyne.TextAlignCenter
	title := heading(titleInstalled)
	title.Alignment = fyne.TextAlignCenter
	body := bodyText(installedBody())
	body.Alignment = fyne.TextAlignCenter
	inner := inset(wizPad8, wizPad, wizPad8, wizPad, vstack(0,
		kick,
		gapH(8),
		title,
		gapH(8),
		body,
		gapH(24),
		c.setupLaunch,
		gapH(12),
		c.setupLaunchHint,
	))
	c.setSetupSheet(inner, 460)
}

func (c *console) paintSetupDeclined() {
	c.setupPhase = "declined"
	c.setupActions.Hide()
	c.setupWorking.Hide()
	c.setupLaunch.Hide()
	c.setupLaunchHint.Hide()
	c.setupProcess.Hide()
	c.setupClose.Show()
	f := copyErrorDeclined()
	f.OnAction = func() { c.app.Quit() }
	inner := pad5(vstack(0, faultCard(f), gapH(16), c.setupClose))
	c.setSetupSheet(inner, 420)
}

func copyErrorDeclined() uiFault {
	return uiFault{
		Title:  "Setup was cancelled",
		Body:   "edr was not installed. You can run setup again when you are ready to accept the license.",
		Detail: "Silent fleet does not show this screen.",
		Action: "Close",
	}
}

func (c *console) setSetupFault(f uiFault) {
	c.setupFaultBox.Objects = nil
	if f.Title != "" {
		c.setupFaultBox.Add(faultCard(f))
	}
	c.setupFaultBox.Refresh()
}

func (c *console) onSetupDecline() {
	c.setSetupFault(uiFault{})
	c.paintSetupDeclined()
}

func (c *console) onSetupAccept() {
	if c.busy {
		return
	}
	if !installerPresent() {
		c.setSetupFault(uiFault{
			Title:  "Installer not found",
			Body:   "Place edr-installer next to this app and try again, or deploy the package silently.",
			Detail: adminDetail(),
			Action: "OK",
		})
		c.paintSetupLicense()
		return
	}
	c.setSetupFault(uiFault{})
	c.setupProcess.SetText(setupStepDoing(0))
	c.setupWorking.SetText("Working…")
	c.paintSetupInstall()
	c.setBusy(true)
	installprogress.Clear()
	c.renderSetupSteps(0, false, false)

	done := make(chan struct {
		out string
		err error
	}, 1)
	go func() {
		out, err := runInstallerPrivileged("install", "--no-start")
		done <- struct {
			out string
			err error
		}{out, err}
	}()
	go func() {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		n := len(setupStepTitles())
		for {
			select {
			case res := <-done:
				fyne.Do(func() {
					c.setBusy(false)
					if res.err != nil {
						step := installprogress.Index(installprogress.Read(), n)
						if step < 0 {
							step = 0
						}
						c.renderSetupSteps(step, false, true)
						c.setupProcess.SetText("Install did not finish.")
						c.setSetupFault(classifyInstallError(res.out + "\n" + res.err.Error()))
						c.paintSetupLicense()
						c.setupAccept.Enable()
						return
					}
					c.renderSetupSteps(n, true, false)
					c.setupProcess.SetText(allChecksPassed)
					c.paintSetupFinish()
					installprogress.Clear()
				})
				return
			case <-tick.C:
				step := installprogress.Read()
				idx := installprogress.Index(step, n)
				if idx < 0 {
					continue
				}
				if idx >= n {
					idx = n - 1
				}
				i := idx
				line := setupStepDoing(i)
				fyne.Do(func() {
					c.renderSetupSteps(i, false, false)
					c.setupProcess.SetText(line)
				})
			}
		}
	}()
}

func (c *console) renderSetupSteps(active int, done, failed bool) {
	c.setupSteps.Objects = nil
	titles := setupStepTitles()
	for i, title := range titles {
		st := checkWait
		switch {
		case failed && i == active:
			st = checkFail
		case done || i < active:
			st = checkOK
		case i == active:
			st = checkRun
		}
		c.setupSteps.Add(checkRow(statusMark(st), title, "", st))
	}
	c.setupSteps.Refresh()
}
