package main

import (
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/installprogress"
	"github.com/razatechofficial/edr/internal/updatecheck"
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

	c.setupLaunch = widget.NewButton("Launch "+productName, c.continueAfterSetup)
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
	c.setupH = h
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
	c.setSetupFault(uiFault{})

	inner := pad5(vstack(0,
		pageHeader(kickerLicense, colorMuted, titleLicense, bodyLicense),
		gapH(16),
		eulaWell,
		gapH(16),
		per,
		gapH(20),
		c.setupActions,
	))
	c.setSetupSheet(inner, 600)
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
	titleTxt := titleInstalled
	bodyTxt := installedBody()
	if c.last.Enrolled {
		titleTxt = "edr is up to date"
		bodyTxt = "Files were replaced. This device is already enrolled."
		c.setupLaunch.SetText("Open edr")
	} else {
		c.setupLaunch.SetText("Launch " + productName)
	}
	title := heading(titleTxt)
	title.Alignment = fyne.TextAlignCenter
	body := bodyText(bodyTxt)
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
			Body:   "The uninstall helper is missing. Reinstall the EDR Agent package, then try again.",
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
						c.presentSetupFault(classifyInstallError(res.out + "\n" + res.err.Error()))
						return
					}
					c.renderSetupSteps(n, true, false)
					c.setupProcess.SetText(allChecksPassed)
					c.last = loadStatus()
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

func installedAgentVersion(st operatorStatus) string {
	if v := strings.TrimSpace(st.Version); v != "" {
		return v
	}
	out, err := runEdrctl("version")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && (strings.EqualFold(fields[0], "edrctl") || strings.EqualFold(fields[0], "edr-agent")) {
			return fields[1]
		}
	}
	return ""
}

func (c *console) paintSetupManage() {
	c.setupPhase = "manage"
	c.setupActions.Hide()
	c.setupWorking.Hide()
	c.setupLaunch.Hide()
	c.setupLaunchHint.Hide()
	c.setupProcess.Hide()
	c.setupClose.Hide()
	c.setSetupFault(uiFault{})

	have := installedAgentVersion(c.last)
	pkg := packageVersion()
	cmp := updatecheck.Compare(have, pkg)
	enrolled := c.last.Enrolled
	running := installedConsoleRunning()

	var kick, title, body string
	primary := widget.NewButton("Continue", c.continueAfterSetup)
	primary.Importance = widget.HighImportance
	repair := widget.NewButton("Reinstall", func() { c.mutateSetup(c.onSetupAccept) })
	remove := widget.NewButton("Uninstall…", func() { c.mutateSetup(c.onUninstallFromSetup) })

	switch {
	case have != "" && cmp < 0:
		kick = "Update available"
		title = "A newer package is ready"
		body = "Replace the installed files, then grant Full Disk Access if macOS asks."
		primary.SetText("Update")
		primary.OnTapped = func() { c.mutateSetup(c.onSetupAccept) }
		repair.Hide()
	case have != "" && cmp > 0:
		kick = "Already installed"
		title = "A newer version is already installed"
		body = "This package is older. Open edr, or replace the files with this build."
		if enrolled {
			primary.SetText("Open edr")
		} else {
			primary.SetText("Continue enrollment")
		}
		repair.SetText("Replace files")
	default:
		kick = "Already installed"
		title = "edr is already on this computer"
		body = "Continue setup, replace the files, or remove the sensor. Full Disk Access is required for the sensor."
		if enrolled {
			primary.SetText("Open edr")
		} else {
			primary.SetText("Continue enrollment")
		}
	}

	verHave := have
	if verHave == "" {
		verHave = "—"
	}
	enrollLine := "Not enrolled"
	if enrolled {
		enrollLine = "Enrolled"
	}
	consoleLine := "Not running"
	if running {
		consoleLine = "Open — quit before update, reinstall, or uninstall"
	}

	status := elevatedWell(8, inset(12, 12, 12, 12, vstack(8,
		manageKV("Installed", verHave),
		manageKV("This package", pkg),
		manageKV("Enrollment", enrollLine),
		manageKV("Dashboard", consoleLine),
	)))

	var banner fyne.CanvasObject
	if running {
		banner = elevatedWell(8, inset(10, 12, 10, 12, captionBlock("EDR Agent is open. Quit it before you update, reinstall, or uninstall — the same Files-in-Use step as Chrome or an MSI.")))
	}

	var foot fyne.CanvasObject
	if running {
		quitBtn := widget.NewButton("Quit EDR Agent", c.onQuitInstalledConsole)
		quitBtn.Importance = widget.HighImportance
		secondaries := []fyne.CanvasObject{repair, remove}
		if !repair.Visible() {
			secondaries = []fyne.CanvasObject{remove}
		}
		foot = vstack(8, quitBtn, primary, container.New(&equalRow{gap: 8}, secondaries...))
	} else {
		secondaries := []fyne.CanvasObject{repair, remove}
		if !repair.Visible() {
			secondaries = []fyne.CanvasObject{remove}
		}
		foot = vstack(8, primary, container.New(&equalRow{gap: 8}, secondaries...))
	}

	introItems := []fyne.CanvasObject{
		pageHeader(kick, colorMuted, title, body),
		gapH(12),
		status,
	}
	if banner != nil {
		introItems = append(introItems, gapH(8), banner)
	}
	intro := pad5(vstack(0, introItems...))
	inner := checklistSheet(intro, canvas.NewRectangle(color.Transparent), checklistFooter(foot))
	c.setSetupSheet(inner, 520)
}

func manageKV(k, v string) fyne.CanvasObject {
	key := canvas.NewText(k, colorMuted)
	key.TextSize = 11
	val := widget.NewLabel(v)
	val.Wrapping = fyne.TextWrapWord
	val.Alignment = fyne.TextAlignTrailing
	return container.NewBorder(nil, nil, key, nil, inset(0, 12, 0, 0, val))
}

func (c *console) mutateSetup(next func()) {
	if installedConsoleRunning() {
		d := dialog.NewConfirm(
			"Quit EDR Agent first",
			"Update, reinstall, and uninstall need the dashboard closed so files and the service can be replaced.",
			func(ok bool) {
				if !ok {
					return
				}
				c.setBusy(true)
				go func() {
					err := quitInstalledConsoleUI()
					fyne.Do(func() {
						c.setBusy(false)
						if err != nil {
							c.presentSetupFault(uiFault{
								Title:  "EDR Agent is still open",
								Body:   err.Error(),
								Action: "OK",
							})
							c.paintSetupManage()
							return
						}
						next()
					})
				}()
			},
			c.win,
		)
		d.SetDismissText("Cancel")
		d.SetConfirmText("Quit and continue")
		d.Show()
		return
	}
	next()
}

func (c *console) onQuitInstalledConsole() {
	c.setBusy(true)
	go func() {
		err := quitInstalledConsoleUI()
		fyne.Do(func() {
			c.setBusy(false)
			if err != nil {
				c.presentSetupFault(uiFault{
					Title:  "Could not quit EDR Agent",
					Body:   err.Error(),
					Action: "OK",
				})
			}
			c.paintSetupManage()
		})
	}()
}

func (c *console) continueAfterSetup() {
	c.last = loadStatus()
	if !c.last.Enrolled {
		c.show(uistate.Enroll)
		return
	}
	if needsOSGrants() {
		c.show(uistate.Permissions)
		return
	}
	next := uistate.InitialScreen(true, true, false, serviceHealthy(c.last.Service))
	if next == uistate.Dash {
		c.showDecoratedDash()
		return
	}
	c.show(next)
}

func (c *console) paintSetupFailed(f uiFault) {
	c.setupPhase = "failed"
	c.setupActions.Hide()
	c.setupWorking.Hide()
	c.setupLaunch.Hide()
	c.setupLaunchHint.Hide()
	c.setupProcess.Hide()
	retry := widget.NewButton(firstNonEmpty(f.Action, "Try again"), func() {
		c.setSetupFault(uiFault{})
		if agentInstalled() && flagSetup {
			c.paintSetupManage()
			return
		}
		c.paintSetupLicense()
	})
	retry.Importance = widget.HighImportance
	closeBtn := widget.NewButton("Close", func() { c.app.Quit() })
	inner := pad5(vstack(0,
		pageHeader("Setup did not finish", colorDanger, f.Title, f.Body),
		gapH(12),
		captionBlock(f.Detail),
		gapH(24),
		retry,
		gapH(8),
		closeBtn,
	))
	c.setSetupSheet(inner, 460)
}

func (c *console) presentSetupFault(f uiFault) {
	c.paintSetupFailed(f)
	msg := widget.NewLabel(strings.TrimSpace(f.Body + "\n\n" + f.Detail))
	msg.Wrapping = fyne.TextWrapWord
	d := dialog.NewCustom(f.Title, firstNonEmpty(f.Action, "OK"), msg, c.win)
	d.Resize(fyne.NewSize(400, 220))
	d.Show()
}

func (c *console) onUninstallFromSetup() {
	d := dialog.NewConfirm(
		"Uninstall EDR Agent",
		"This removes the sensor, rules, models, certificates, keys, and data. Administrator authentication is required.",
		func(ok bool) {
			if !ok {
				return
			}
			c.setBusy(true)
			go func() {
				out, err := runInstallerPrivileged("uninstall")
				fyne.Do(func() {
					c.setBusy(false)
					if err != nil {
						c.presentSetupFault(classifyInstallError(out + "\n" + err.Error()))
						return
					}
					c.enterRemovedState()
				})
			}()
		},
		c.win,
	)
	d.SetDismissText("Cancel")
	d.SetConfirmText("Uninstall")
	d.Show()
}

func (c *console) enterRemovedState() {
	c.removed = true
	c.last = operatorStatus{}
	c.busy = false
	c.flyoutOpen = false
	if c.pop != nil {
		c.pop.Hide()
	}
	if desk, ok := c.app.(desktop.App); ok {
		desk.SetSystemTrayMenu(nil)
	}
	if c.dashAction != nil {
		c.dashAction.Hide()
	}
	c.paintSetupRemoved()
	c.show(uistate.Setup)
}

func (c *console) paintSetupRemoved() {
	c.setupPhase = "removed"
	c.setupActions.Hide()
	c.setupWorking.Hide()
	c.setupLaunch.Hide()
	c.setupLaunchHint.Hide()
	c.setupProcess.Hide()
	c.setupClose.Show()
	c.setSetupFault(uiFault{})

	closeBtn := widget.NewButton("Close", func() { c.app.Quit() })
	closeBtn.Importance = widget.HighImportance
	actions := []fyne.CanvasObject{closeBtn}
	if flagSetup {
		again := widget.NewButton("Install again", func() {
			c.removed = false
			c.permAutoOpened = false
			c.paintSetupLicense()
			c.show(uistate.Setup)
		})
		actions = []fyne.CanvasObject{again, closeBtn}
	}

	inner := pad5(vstack(0,
		pageHeader("Uninstalled", colorDanger, "EDR Agent was removed", "This computer is no longer protected. The sensor, login items, and leftover files were removed."),
		gapH(24),
		vstack(8, actions...),
	))
	c.setSetupSheet(inner, 420)
}

func (c *console) paintOrphanConsole() {
	c.setupPhase = "orphan"
	c.setupActions.Hide()
	c.setupWorking.Hide()
	c.setupLaunch.Hide()
	c.setupLaunchHint.Hide()
	c.setupProcess.Hide()
	c.setupClose.Show()
	c.setSetupFault(uiFault{})
	closeBtn := widget.NewButton("Close", func() { c.app.Quit() })
	closeBtn.Importance = widget.HighImportance
	inner := pad5(vstack(0,
		pageHeader("Not installed", colorMuted, "edr is not on this computer", "Install the EDR Agent package from your console download, or close this window if you already uninstalled."),
		gapH(24),
		closeBtn,
	))
	c.setSetupSheet(inner, 400)
}
