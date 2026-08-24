package main

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func (c *console) buildEnroll() fyne.CanvasObject {
	c.host = widget.NewEntry()
	c.host.SetPlaceHolder(xdrclient.DefaultEnrollmentHost)
	c.host.Text = c.app.Preferences().StringWithFallback("enroll.host", xdrclient.DefaultEnrollmentHost)

	c.token = widget.NewPasswordEntry()
	c.token.SetPlaceHolder("One-time enrollment token")

	c.enrollHint = widget.NewLabel("Enter the host and token from the XDR console.")
	c.enrollHint.Wrapping = fyne.TextWrapWord
	c.enrollHint.Alignment = fyne.TextAlignCenter

	c.testBtn = widget.NewButtonWithIcon("Test connection", theme.SearchIcon(), c.onTestConnection)
	c.testBtn.Importance = widget.MediumImportance
	c.enrollBtn = widget.NewButtonWithIcon("Enroll device", theme.ConfirmIcon(), c.onEnroll)
	c.enrollBtn.Importance = widget.HighImportance

	hero := canvas.NewText("Device Enrollment", colorText)
	hero.TextSize = 24
	hero.TextStyle = fyne.TextStyle{Bold: true}
	hero.Alignment = fyne.TextAlignCenter
	sub := canvas.NewText("Configure agent connection settings", colorMuted)
	sub.TextSize = 13
	sub.Alignment = fyne.TextAlignCenter

	hostLabel := caption("SERVER HOST")
	tokenLabel := caption("ENROLLMENT TOKEN")

	body := container.NewVBox(
		c.chrome(c.settingsButton()),
		layout.NewSpacer(),
		container.NewCenter(widget.NewIcon(theme.ComputerIcon())),
		container.NewCenter(hero),
		container.NewCenter(sub),
		widget.NewSeparator(),
		hostLabel,
		fieldWithIcon(theme.ComputerIcon(), c.host),
		tokenLabel,
		fieldWithIcon(theme.VisibilityOffIcon(), c.token),
		c.enrollHint,
		c.testBtn,
		c.enrollBtn,
		layout.NewSpacer(),
	)
	c.enrollContent = container.NewPadded(body)
	return c.enrollContent
}

func (c *console) onTestConnection() {
	if c.busy {
		return
	}
	host := strings.TrimSpace(c.host.Text)
	c.setBusy(true)
	c.enrollHint.SetText("Checking reachability…")
	go func() {
		ok, detail := networkCheck(host)
		fyne.Do(func() {
			c.setBusy(false)
			if ok {
				c.enrollHint.SetText(detail)
			} else {
				c.enrollHint.SetText(detail)
			}
		})
	}()
}

func (c *console) onEnroll() {
	if c.busy {
		return
	}
	host := strings.TrimSpace(c.host.Text)
	if host == "" {
		host = xdrclient.DefaultEnrollmentHost
	}
	tok := strings.TrimSpace(c.token.Text)
	if tok == "" {
		c.enrollHint.SetText("Paste the enrollment token from the XDR console.")
		return
	}
	c.app.Preferences().SetString("enroll.host", host)
	c.setBusy(true)
	c.enrollHint.SetText("Enrolling this device…")
	go func() {
		out, err := runEdrctlPrivileged("enroll", "--host", host, "--token", tok)
		st := loadStatus()
		fyne.Do(func() {
			c.setBusy(false)
			c.last = st
			if err != nil && !st.Enrolled {
				msg := strings.TrimSpace(out)
				if msg == "" {
					msg = err.Error()
				}
				c.enrollHint.SetText(clipErr(msg))
				return
			}
			c.token.SetText("")
			c.show(uistate.Preflight)
		})
	}()
}
