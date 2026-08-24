package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildPreflight() fyne.CanvasObject {
	c.preflightBox = container.NewVBox()
	c.preflightHint = widget.NewLabel("Validating pre-flight requirements.")
	c.preflightHint.Wrapping = fyne.TextWrapWord
	c.preflightHint.Alignment = fyne.TextAlignCenter

	c.grantBtn = widget.NewButtonWithIcon("Open permission settings", theme.SettingsIcon(), func() {
		_ = openFullDiskAccessSettings()
		c.preflightHint.SetText("Enable EDR Agent Sensor, then Recheck.")
	})
	c.grantBtn.Importance = widget.MediumImportance
	if !needsFullDiskAccess() {
		c.grantBtn.Hide()
	}

	recheck := widget.NewButtonWithIcon("Recheck", theme.ViewRefreshIcon(), func() {
		go c.runPreflight()
	})

	c.startAgentBtn = widget.NewButtonWithIcon("Start agent", theme.MediaPlayIcon(), c.onStartAgent)
	c.startAgentBtn.Importance = widget.HighImportance
	c.startAgentBtn.Disable()

	title := heading("System Check")
	title.Alignment = fyne.TextAlignCenter
	sub := canvas.NewText("Validating pre-flight requirements", colorMuted)
	sub.TextSize = 13
	sub.Alignment = fyne.TextAlignCenter

	body := container.NewVBox(
		c.chrome(c.settingsButton()),
		layout.NewSpacer(),
		container.NewCenter(title),
		container.NewCenter(sub),
		card(c.preflightBox),
		c.preflightHint,
		c.grantBtn,
		recheck,
		c.startAgentBtn,
		layout.NewSpacer(),
	)
	c.preflightContent = container.NewPadded(body)
	return c.preflightContent
}

func (c *console) renderPreflight() {
	c.preflightBox.Objects = nil
	allOK := len(c.preflightItems) > 0
	for _, it := range c.preflightItems {
		if it.State != checkOK {
			allOK = false
		}
		c.preflightBox.Add(preflightRow(it))
	}
	c.preflightBox.Refresh()
	c.checksOK = allOK
	if allOK {
		c.startAgentBtn.Enable()
		c.preflightHint.SetText("All checks passed. Start the sensor to begin streaming.")
	} else {
		c.startAgentBtn.Disable()
	}
}

func preflightRow(it preflightItem) fyne.CanvasObject {
	statusCol, ico := checkVisual(it.State)
	code := caption(it.Code)
	title := widget.NewLabel(it.Title)
	title.Wrapping = fyne.TextWrapWord
	detail := widget.NewLabel(it.Detail)
	detail.Wrapping = fyne.TextWrapWord
	if it.Detail == "" {
		detail.Hide()
	}
	st := canvas.NewText(it.State.Label(), statusCol)
	st.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	st.TextSize = 12
	left := container.NewHBox(widget.NewIcon(ico), container.NewVBox(code, title, detail))
	return container.NewPadded(container.NewBorder(nil, widget.NewSeparator(), nil, st, left))
}

func checkVisual(s checkState) (color.Color, fyne.Resource) {
	switch s {
	case checkOK:
		return colorOK, theme.ConfirmIcon()
	case checkRun:
		return colorCyan, theme.ViewRefreshIcon()
	case checkFail:
		return colorDanger, theme.ErrorIcon()
	default:
		return colorMuted, theme.RadioButtonIcon()
	}
}

func (c *console) runPreflight() {
	host := ""
	if c.host != nil {
		host = c.host.Text
	}
	items := newPreflightItems()
	fyne.DoAndWait(func() {
		c.preflightItems = items
		c.startAgentBtn.Disable()
		c.renderPreflight()
	})
	for i := range items {
		items[i].State = checkRun
		fyne.DoAndWait(func() {
			c.preflightItems = items
			c.renderPreflight()
		})
		ok, detail := runOneCheck(items[i].ID, host)
		if ok {
			items[i].State = checkOK
		} else {
			items[i].State = checkFail
		}
		items[i].Detail = detail
		fyne.DoAndWait(func() {
			c.preflightItems = items
			c.renderPreflight()
		})
	}
}

func (c *console) onStartAgent() {
	if c.busy || !c.checksOK {
		return
	}
	c.setBusy(true)
	c.preflightHint.SetText("Starting the sensor…")
	go func() {
		out, err := runEdrctlPrivileged("start")
		st := loadStatus()
		fyne.Do(func() {
			c.setBusy(false)
			c.last = st
			if err != nil && !serviceHealthy(st.Service) {
				msg := clipErr(out)
				if msg == "" && err != nil {
					msg = err.Error()
				}
				c.preflightHint.SetText(msg)
				return
			}
			c.show(uistate.Dash)
		})
	}()
}
