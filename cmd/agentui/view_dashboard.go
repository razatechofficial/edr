package main

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/config"
	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/updatecheck"
)

func (c *console) buildDashboard() fyne.CanvasObject {
	c.glow = newGlowBG(colorOK)
	c.spark = newAreaSpark(colorCyan)
	c.ramBar = newRamBar()
	c.cpuHist = make([]float64, 0, 12)

	c.heroFace = newHeroFace()
	c.healthTitle = canvas.NewText("Protected", colorText)
	c.healthTitle.TextSize = dashTitleSize
	c.healthTitle.TextStyle = fyne.TextStyle{Bold: true}

	c.sensorLive = newLiveDot()
	c.sensorLamp = canvas.NewText("Sensor Running", colorText)
	c.sensorLamp.TextSize = 11
	c.streamLamp = canvas.NewText("Live", colorText)
	c.streamLamp.TextSize = 11
	c.streamMark = newIconDot("wifi", colorOK)

	c.bannerBg = canvas.NewRectangle(colorWell)
	c.bannerBg.CornerRadius = 12
	c.bannerBg.StrokeWidth = 1
	c.bannerBg.StrokeColor = withAlpha(colorOK, 0x44)
	c.bannerText = canvas.NewText("", colorText)
	c.bannerText.TextSize = 12
	c.bannerWrap = container.NewStack(c.bannerBg, inset(dashBannerPadY, dashBannerPadX, dashBannerPadY, dashBannerPadX, c.bannerText))
	c.bannerWrap.Hide()

	c.cpuVal = numText("0.0", 32, colorText)
	c.cpuUnit = canvas.NewText("%", colorTertiary)
	c.cpuUnit.TextSize = 12
	c.cpuHint = canvas.NewText("Sensor idle", colorTertiary)
	c.cpuHint.TextSize = 11

	c.ramVal = numText("0", 32, colorText)
	c.ramUnit = canvas.NewText("MB", colorTertiary)
	c.ramUnit.TextSize = 12
	c.ramHint = canvas.NewText("—", colorTertiary)
	c.ramHint.TextSize = 11

	c.eventsVal = numText("—", 22, colorText)
	c.threatsVal = numText("—", 22, colorText)
	c.blocksVal = numText("—", 22, colorText)
	c.eventsVal.Alignment = fyne.TextAlignCenter
	c.threatsVal.Alignment = fyne.TextAlignCenter
	c.blocksVal.Alignment = fyne.TextAlignCenter

	c.uptimeVal = canvas.NewText("— · Rules —", colorTertiary)
	c.uptimeVal.TextSize = 11
	c.agentLine = canvas.NewText("—", color.NRGBA{R: 0xEB, G: 0xEB, B: 0xF5, A: 0x52})
	c.agentLine.TextSize = 10
	c.agentLine.TextStyle = fyne.TextStyle{Monospace: true}

	c.dashAction = widget.NewButton("Start "+productName, c.onDashAction)
	c.dashAction.Importance = widget.HighImportance
	c.dashAction.Hide()
	c.dashFaultBox = container.NewVBox()
	c.dashFaultBox.Hide()

	pills := hstack(dashPillGap,
		pill(c.sensorLive, c.sensorLamp),
		pill(lockH(12, c.streamMark), c.streamLamp),
	)
	titleCol := vstack(0, c.healthTitle, gapH(dashPillsMT), pills)
	header := vstack(dashBannerMT, heroRow(c.heroFace, titleCol), c.bannerWrap)

	cpuTile := resourceTile("EDR CPU", c.cpuVal, c.cpuUnit, c.cpuHint, lockH(dashSparkH, c.spark))
	ramTile := resourceTile("EDR RAM", c.ramVal, c.ramUnit, c.ramHint, pinTopH(dashSparkH, c.ramBar))
	tiles := splitRow(dashTileGap, cpuTile, ramTile)

	sep := func() fyne.CanvasObject {
		line := canvas.NewRectangle(color.NRGBA{R: 255, G: 255, B: 255, A: 0x14})
		line.SetMinSize(fyne.NewSize(1, 1))
		return line
	}
	metricsBg := canvas.NewRectangle(colorTile)
	metricsBg.CornerRadius = 16
	metricsBg.StrokeColor = colorHairline
	metricsBg.StrokeWidth = 1
	metricsInner := container.New(&metricsStrip{},
		metricCell("activity", colorCyan, c.eventsVal, "EVENTS"),
		sep(),
		metricCell("alert", colorWarn, c.threatsVal, "THREATS"),
		sep(),
		metricCell("ban", colorOK, c.blocksVal, "BLOCKED"),
	)
	metrics := container.NewStack(metricsBg, inset(dashMetricsPadY, dashMetricsPadX, dashMetricsPadY, dashMetricsPadX, metricsInner))

	footLine := canvas.NewRectangle(color.NRGBA{R: 255, G: 255, B: 255, A: 0x0F})
	footLine.SetMinSize(fyne.NewSize(1, 1))
	foot := vstack(0, footLine, inset(dashFootPadY, dashFootPadX, dashFootPadY, dashFootPadX,
		container.NewBorder(nil, nil, c.uptimeVal, c.agentLine, nil),
	))

	tailInner := container.New(&gapStack{axis: stackV, gap: 12}, c.dashFaultBox, c.dashAction)
	c.dashTail = container.New(&padLayout{4, dashBodyPadX, dashBodyPadY, dashBodyPadX}, tailInner)
	c.dashTail.Hide()
	body := vstack(0, tiles, gapH(dashMetricsMT), metrics)
	c.dashSheet = vstack(0,
		inset(dashHeaderPadT, dashHeaderPadX, dashHeaderPadB, dashHeaderPadX, header),
		inset(dashBodyPadY, dashBodyPadX, dashBodyPadY, dashBodyPadX, body),
		c.dashTail,
		foot,
	)
	c.dashContent = container.NewStack(
		c.glow,
		newDragFrame(c.dashSheet, c.dashHost),
	)
	if c.pop != nil {
		c.pop.SetPadded(false)
		c.pop.SetContent(c.dashContent)
	}
	return c.dashContent
}

func (c *console) dashHost() fyne.Window {
	if c.pop != nil {
		return c.pop
	}
	return c.win
}

func (c *console) dashCanvas() fyne.Canvas {
	if c.pop != nil {
		return c.pop.Canvas()
	}
	return c.win.Canvas()
}

func pill(mark fyne.CanvasObject, label *canvas.Text) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorPill)
	bg.CornerRadius = 12
	bg.StrokeColor = colorHairline
	bg.StrokeWidth = 1
	row := hstack(dashPillMark, mark, label)
	return container.NewStack(bg, inset(dashPillPadY, dashPillPadX, dashPillPadY, dashPillPadX, row))
}

func resourceTile(label string, value, unit, hint *canvas.Text, child fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorTile)
	bg.CornerRadius = 16
	bg.StrokeColor = colorHairline
	bg.StrokeWidth = 1
	cap := labelCaps(label, 10, colorTertiary)
	nums := hstack(4, value, unit)
	body := vstack(0, cap, gapH(dashNumMT), nums, gapH(dashSparkMT), child, gapH(dashHintMT), hint)
	return container.NewStack(bg, inset(dashTilePadY, dashTilePadX, dashTilePadY, dashTilePadX, body))
}

func metricCell(kind string, wellCol color.NRGBA, value *canvas.Text, label string) fyne.CanvasObject {
	cap := labelCaps(label, 10, colorTertiary)
	cap.Alignment = fyne.TextAlignCenter
	value.Alignment = fyne.TextAlignCenter
	return vstack(0, metricWell(kind, wellCol), gapH(dashMetricValMT), value, cap)
}

func (c *console) applyDashboard(st operatorStatus, res resourceSnapshot) {
	if c.removed {
		return
	}
	k, lamps := decorateHealth(st)
	hero := colorOK
	kind := heroOK
	switch k {
	case uistate.Protected:
		hero = colorOK
		kind = heroOK
		if lamps.Banner != "" {
			hero = colorWarn
			kind = heroAlert
		}
	case uistate.Contained:
		hero = colorDanger
		kind = heroOff
	case uistate.Degraded:
		hero = colorWarn
		kind = heroAlert
	default:
		hero = colorDanger
		kind = heroOff
	}

	c.glow.SetHero(hero)
	if c.heroFace != nil {
		c.heroFace.Set(hero, kind)
	}
	c.healthTitle.Text = lamps.Title
	c.healthTitle.Color = colorText
	c.healthTitle.Refresh()

	sensorCol := lampColor(lamps.Sensor)
	streamCol := lampColor(lamps.Stream)
	if c.sensorLive != nil {
		c.sensorLive.Set(sensorCol, lamps.Sensor == "Running")
	}
	c.sensorLamp.Text = "Sensor " + lamps.Sensor
	c.sensorLamp.Refresh()
	c.streamLamp.Text = lamps.Stream
	c.streamLamp.Refresh()
	wifi := "wifi"
	if lamps.Stream != "Live" {
		wifi = "wifi-off"
	}
	if c.streamMark != nil {
		c.streamMark.Set(wifi, streamCol)
	}

	if lamps.Banner != "" {
		c.bannerText.Text = lamps.Banner
		c.bannerText.Refresh()
		c.bannerBg.StrokeColor = withAlpha(hero, 0x44)
		c.bannerBg.Refresh()
		c.bannerWrap.Show()
	} else {
		c.bannerWrap.Hide()
	}

	stopped := !serviceHealthy(st.Service)
	switch {
	case stopped:
		c.cpuVal.Text = "0.0"
		c.cpuUnit.Text = "%"
		c.cpuHint.Text = "Sensor idle"
		c.ramVal.Text, c.ramUnit.Text = formatAgentRAM(res.AgentMemMB)
		c.eventsVal.Text = "—"
		c.threatsVal.Text = "—"
		c.blocksVal.Text = "—"
		c.uptimeVal.Text = "— · Rules —"
	default:
		c.cpuVal.Text = fmt.Sprintf("%.1f", res.AgentCPU)
		c.cpuUnit.Text = "%"
		c.cpuHint.Text = cpuBreakdown(res)
		c.ramVal.Text, c.ramUnit.Text = formatAgentRAM(res.AgentMemMB)
		c.eventsVal.Text = formatCount(st.EventsProc)
		c.threatsVal.Text = formatCount(st.Detections)
		c.blocksVal.Text = formatCount(st.Blocks)
		c.uptimeVal.Text = rulesLine(st.Uptime, st.RulesCount)
	}
	c.cpuVal.Refresh()
	c.cpuUnit.Refresh()
	c.cpuHint.Refresh()
	c.ramVal.Refresh()
	c.ramUnit.Refresh()
	c.ramHint.Text = ramBreakdown(res)
	c.ramHint.Refresh()
	c.eventsVal.Refresh()
	c.threatsVal.Refresh()
	c.blocksVal.Refresh()
	c.uptimeVal.Refresh()
	c.agentLine.Text = compactAgentID(st.AgentID)
	c.agentLine.Refresh()

	edr, other, free := res.memShares()
	if stopped {
		edr, other, free = 0, other, free
		if edr+other+free == 0 {
			free = 1
		}
	}
	c.ramBar.SetShares(edr, other, free)
	c.pushCPU(res.AgentCPU, stopped)
	c.updateDashAction(st)
}

func lampColor(s string) color.NRGBA {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "running", "live":
		return colorOK
	case "idle":
		return color.NRGBA{R: 0xEB, G: 0xEB, B: 0xF5, A: 0x59}
	case "queued", "retrying", "limited":
		return colorWarn
	case "stopped":
		return colorDanger
	default:
		return colorMuted
	}
}

func (c *console) updateDashAction(st operatorStatus) {
	if c.dashAction == nil {
		return
	}
	if c.removed {
		c.dashAction.Hide()
		return
	}
	was := c.dashTail != nil && c.dashTail.Visible()
	show := false
	if !st.Enrolled {
		c.dashAction.SetText("Enroll this device")
		show = true
	} else if !serviceHealthy(st.Service) {
		c.dashAction.SetText("Start " + productName)
		show = true
	} else if !st.IngestConfigured || !st.IngestEnv || !st.IngestOK {
		if st.IngestConfigured && st.IngestEnv {
			c.dashAction.SetText("Retry stream")
		} else {
			c.dashAction.SetText("Connect stream")
		}
		show = true
	}
	if show {
		c.dashAction.Show()
		if c.dashTail != nil {
			c.dashTail.Show()
		}
	} else {
		c.dashAction.Hide()
		if c.dashTail != nil && (c.dashFaultBox == nil || !c.dashFaultBox.Visible()) {
			c.dashTail.Hide()
		}
	}
	now := c.dashTail != nil && c.dashTail.Visible()
	if was != now {
		c.fitDash()
	}
}

func (c *console) onDashAction() {
	if c.busy {
		return
	}
	if !c.last.Enrolled {
		c.show(uistate.Enroll)
		return
	}
	c.startSensor()
}

func (c *console) setDashFault(f uiFault) {
	if c.dashFaultBox == nil {
		return
	}
	c.dashFaultBox.Objects = nil
	if f.Title != "" {
		c.dashFaultBox.Add(faultCard(f))
		c.dashFaultBox.Show()
	} else {
		c.dashFaultBox.Hide()
	}
	c.dashFaultBox.Refresh()
}

func (c *console) pushCPU(pct float64, stopped bool) {
	if stopped {
		pct = 0.2
	}
	c.cpuHist = append(c.cpuHist, pct)
	if len(c.cpuHist) > 12 {
		c.cpuHist = c.cpuHist[len(c.cpuHist)-12:]
	}
	if c.spark != nil {
		c.spark.SetValues(c.cpuHist)
	}
}

func (c *console) dismissToTray() {
	c.flyoutOpen = false
	if c.win != nil {
		c.win.Hide()
	}
	if c.pop != nil {
		c.pop.Hide()
	}
}

func (c *console) flyoutWindow() fyne.Window {
	if c.pop != nil {
		return c.pop
	}
	return c.win
}

func (c *console) showDash() {
	if c.removed {
		c.enterRemovedState()
		return
	}
	c.screen = uistate.Dash
	lastTrayTap = time.Now()
	if c.win != nil && c.win != c.flyoutWindow() {
		c.win.Hide()
	}
	target := c.flyoutWindow()
	if target == nil {
		return
	}
	target.SetPadded(false)
	if c.dashContent != nil && target.Content() != c.dashContent {
		target.SetContent(c.dashContent)
	}
	res := sampleResources(c.last)
	c.applyDashboard(c.last, res)
	c.refreshTray(c.last, res)
	c.flyoutOpen = true
	c.fitDash()
	target.Show()
	target.RequestFocus()
	h := c.dashHeight()
	placeNearTray(target, popoverW, h, true, true)
}

func (c *console) dashHeight() float32 {
	h := popoverH
	if c.dashSheet != nil {
		h = c.dashSheet.MinSize().Height
	}
	if h < 360 {
		h = 360
	}
	if h > 560 {
		h = 560
	}
	return h
}

func (c *console) fitDash() {
	target := c.flyoutWindow()
	if target == nil {
		return
	}
	h := c.dashHeight()
	if target.Content() != nil {
		got := target.Canvas().Size()
		if abs32(got.Width-popoverW) < 1 && abs32(got.Height-h) < 1 {
			return
		}
	}
	nativeResizeKeepTop(target, popoverW, h)
	target.Resize(fyne.NewSize(popoverW, h))
}

func (c *console) showPopover() {
	c.showDash()
}

func (c *console) showDecoratedDash() {
	c.showDash()
}

func (c *console) returnToDash() {
	c.showDash()
}

func formatBytesMB(n int64) string {
	if n < 1024*1024 {
		return fmt.Sprintf("%d KB", n/1024)
	}
	return fmt.Sprintf("%.0f MB", float64(n)/(1024*1024))
}

func certExpiring(rfc3339 string) (bool, int) {
	if rfc3339 == "" {
		return false, 0
	}
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return false, 0
	}
	d := int(time.Until(t).Hours() / 24)
	if d >= 0 && d <= 7 {
		return true, d
	}
	return false, d
}

func (c *console) onCheckUpdates() {
	c.bannerText.Text = "Checking for updates…"
	c.bannerText.Refresh()
	c.bannerWrap.Show()
	go func() {
		r := updatecheck.Check(productVersion, updateCatalogURL(), nil)
		fyne.Do(func() {
			msg := "EDR Agent is up to date (" + r.Current + ")."
			switch {
			case r.Skipped != "":
				msg = "Updates are managed by your organization (MDM / catalog not set)."
			case r.Error != "":
				msg = "Could not reach the update catalog."
			case r.Update:
				msg = "Update available: " + r.Latest + " (this device is " + r.Current + "). Install as administrator."
			}
			c.bannerText.Text = msg
			c.bannerText.Refresh()
			c.bannerWrap.Show()
		})
	}()
}

func updateCatalogURL() string {
	p := platform.ResolveConfigFile()
	if p == "" {
		return ""
	}
	cfg, err := config.Load(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.XDR.UpdateCatalogURL)
}

func (c *console) onUninstall() {
	parent := c.dashHost()
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
						c.setDashFault(classifyInstallError(out + "\n" + err.Error()))
						return
					}
					c.enterRemovedState()
				})
			}()
		},
		parent,
	)
	d.SetDismissText("Cancel")
	d.SetConfirmText("Uninstall")
	d.Show()
}
