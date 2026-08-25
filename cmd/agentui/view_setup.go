package main

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildSetup() fyne.CanvasObject {
	c.setupHint = widget.NewLabel("Read and accept to install. Silent fleet skips this screen — the organization accepts by deploying the package.")
	c.setupHint.Wrapping = fyne.TextWrapWord
	c.setupFaultBox = container.NewVBox()
	c.setupSteps = container.NewVBox()

	eula := widget.NewLabel(eulaText)
	eula.Wrapping = fyne.TextWrapWord
	eulaScroll := container.NewVScroll(eula)
	eulaScroll.SetMinSize(fyne.NewSize(0, 168))

	c.setupAccept = widget.NewButton("Accept", c.onSetupAccept)
	c.setupAccept.Importance = widget.HighImportance
	c.setupDecline = widget.NewButton("Decline", c.onSetupDecline)
	c.setupActions = container.NewGridWithColumns(2, c.setupDecline, c.setupAccept)

	c.setupLaunch = widget.NewButton("Launch EDR Agent", func() {
		c.show(uistate.Enroll)
	})
	c.setupLaunch.Importance = widget.HighImportance
	c.setupLaunch.Hide()
	c.setupLaunchHint = widget.NewLabel("Launch opens first-run enrollment. The sensor starts after identity and checks pass.")
	c.setupLaunchHint.Wrapping = fyne.TextWrapWord
	c.setupLaunchHint.Hide()

	c.setupClose = widget.NewButton("Close", func() { c.app.Quit() })
	c.setupClose.Hide()

	per := container.NewVBox(
		widget.NewLabelWithStyle("Installs for all users of this computer", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		bodyText("Required for host monitoring. This is not a “this user only” app."),
	)

	header := pageHeader("License agreement", colorAccent, "Software license", "")
	header = container.NewVBox(header, c.setupHint)
	body := container.NewVBox(card(eulaScroll), card(per), c.setupFaultBox, c.setupSteps)
	foot := container.NewVBox(c.setupActions, c.setupLaunch, c.setupLaunchHint, c.setupClose)
	c.setupBody = body
	c.setupContent = wizardPage(header, body, foot)
	return c.setupContent
}

func copyErrorDeclined() uiFault {
	return uiFault{
		Title:  "Setup was cancelled",
		Body:   "EDR Agent was not installed. You can run setup again when you are ready to accept the license.",
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
	c.setSetupFault(copyErrorDeclined())
	c.setupActions.Hide()
	c.setupLaunch.Hide()
	if c.setupLaunchHint != nil {
		c.setupLaunchHint.Hide()
	}
	c.setupClose.Show()
	c.setupHint.SetText("You can run setup again when you are ready to accept the license.")
}

func (c *console) onSetupAccept() {
	if c.busy {
		return
	}
	if !installerPresent() {
		c.setSetupFault(uiFault{
			Title:  "Installer not found",
			Body:   "Place edr-installer next to EDR Agent and try again, or deploy the package silently.",
			Detail: adminDetail(),
			Action: "OK",
		})
		return
	}
	c.setSetupFault(uiFault{})
	c.setupActions.Hide()
	c.setupHint.SetText("Copies files and registers the machine-wide service. No token on this screen.")
	c.setBusy(true)
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
		active := 0
		tick := time.NewTicker(900 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case res := <-done:
				fyne.Do(func() {
					c.setBusy(false)
					if res.err != nil {
						c.renderSetupSteps(active, false, true)
						c.setSetupFault(classifyInstallError(res.out + "\n" + res.err.Error()))
						c.setupActions.Show()
						c.setupAccept.Enable()
						return
					}
					c.renderSetupSteps(3, true, false)
					c.setupHint.SetText(installedBody())
					c.setupLaunch.Show()
					if c.setupLaunchHint != nil {
						c.setupLaunchHint.Show()
					}
					c.setupActions.Hide()
				})
				return
			case <-tick.C:
				if active < 2 {
					active++
					a := active
					fyne.Do(func() { c.renderSetupSteps(a, false, false) })
				}
			}
		}
	}()
}

func installedBody() string {
	switch {
	case isDarwin():
		return "This Mac is not enrolled yet. Launch EDR Agent to bind device identity, then grant access in System Settings."
	case isWindows():
		return "This PC is not enrolled yet. Launch EDR Agent to bind device identity, then allow the firewall if Windows asks."
	default:
		return "This host is not enrolled yet. Run sudo edrctl enroll to bind device identity."
	}
}

func setupStepTitles() []string {
	switch {
	case isDarwin():
		return []string{"macOS 12+ and disk space", "Install EDR Agent.app", "Register LaunchDaemon"}
	case isWindows():
		return []string{"Windows 10+ and disk space", "Install to Program Files", "Register EDRAgent service"}
	default:
		return []string{"Kernel and disk space", "Install deb/rpm package", "Register systemd unit"}
	}
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
		c.setupSteps.Add(listRow(statusMark(st), title, "", false))
	}
	c.setupSteps.Refresh()
}
