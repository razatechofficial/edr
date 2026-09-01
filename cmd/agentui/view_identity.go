package main

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func (c *console) buildIdentity() fyne.CanvasObject {
	c.identityHint = widget.NewLabel("This device creates a key, sends a certificate request, and stores the signed cert in the OS keystore. The private key never leaves this computer.")
	c.identityHint.Wrapping = fyne.TextWrapWord

	hero := heroWell(wizHero, colorAccent, "shield")
	kick := kicker("ENROLLING", colorAccent)
	title := heading("Securing device identity")
	header := iconBand(wizHero, wizHeroGap, hero, vstack(4, kick, title))

	c.identityBar = newSmoothBar()
	c.identityCount = canvas.NewText("0/7", colorTertiary)
	c.identityCount.TextSize = 11
	c.identityDoing = canvas.NewText(identityWaiting(), colorMuted)
	c.identityDoing.TextSize = 12

	c.identityBox = container.New(&gapStack{axis: stackV, gap: 0})
	meter := container.New(&meterLay{}, c.identityBar, c.identityCount)

	lockIco := canvas.NewImageFromResource(drawMiniIcon("lock", colorAccent))
	lockIco.FillMode = canvas.ImageFillContain
	lockIco.SetMinSize(fyne.NewSize(14, 14))
	lockTxt := widget.NewLabel("Private key never leaves this device. Only the certificate request is sent.")
	lockTxt.Wrapping = fyne.TextWrapWord
	lockTxt.Importance = widget.LowImportance
	lockBg := canvas.NewRectangle(color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0x1A})
	lockBg.CornerRadius = 12
	lockBg.StrokeColor = color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0x38}
	lockBg.StrokeWidth = 1
	lock := container.NewStack(lockBg, inset(12, 14, 12, 14,
		iconBand(14, 10, lockIco, lockTxt),
	))

	sheet := pad5(vstack(0,
		header,
		gapH(12),
		c.identityHint,
		gapH(16),
		meter,
		gapH(8),
		c.identityDoing,
		gapH(16),
		c.identityBox,
		gapH(8),
		lock,
	))
	c.identityContent = firstRunFrame(sheet)
	return c.identityContent
}

func (c *console) renderIdentity(active int, done, failed, waiting bool) {
	c.identityBox.Objects = nil
	titles := identityTitles()
	n := len(titles)
	passed := active
	if done {
		passed = n
	}
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
		c.identityBox.Add(timelineRow(st, title, i == n-1, st == checkOK))
	}
	frac := float64(passed) / float64(n)
	if !done && !failed && active < n {
		frac = (float64(passed) + 0.45) / float64(n)
	}
	if waiting && !done && !failed {
		frac = 0.08
	}
	if c.identityBar != nil {
		c.identityBar.SetValue(frac)
	}
	shown := passed
	if !done && active < n {
		shown = passed + 1
	}
	if shown > n {
		shown = n
	}
	if waiting && !done && !failed {
		shown = 1
	}
	if c.identityCount != nil {
		c.identityCount.Text = fmt.Sprintf("%d/%d", shown, n)
		c.identityCount.Refresh()
	}
	if c.identityDoing != nil {
		switch {
		case failed:
			c.identityDoing.Text = "Enrollment did not finish."
			c.identityDoing.Color = colorDanger
		case done:
			c.identityDoing.Text = "Identity bound. Opening receipt…"
			c.identityDoing.Color = colorOK
		case waiting:
			c.identityDoing.Text = identityWaiting()
			c.identityDoing.Color = colorMuted
		default:
			c.identityDoing.Text = identityDoing(active)
			c.identityDoing.Color = colorMuted
		}
		c.identityDoing.Refresh()
	}
	c.identityBox.Refresh()
}

const identityStepHold = time.Second

func (c *console) startIdentity(host, token string) {
	n := len(identityTitles())
	c.renderIdentity(0, false, false, true)
	c.setBusy(true)
	xdrclient.ClearEnrollProgress(platform.DataDir())

	type result struct {
		out string
		err error
		st  operatorStatus
	}
	doneCh := make(chan result, 1)
	go func() {
		out, err := runEdrctlPrivileged("enroll", "--host", host, "--token", token)
		st := loadStatus()
		if fields := parseEnrollReceipt(out); fields["agent_id"] != "" {
			st.Enrolled = true
			st.AgentID = firstNonEmpty(st.AgentID, fields["agent_id"])
			st.MachineID = firstNonEmpty(st.MachineID, fields["machine_id"])
			st.CertExpiry = firstNonEmpty(st.CertExpiry, fields["cert_not_after"])
		}
		doneCh <- result{out, err, st}
	}()

	go func() {
		ui := 0
		target := 0
		waiting := true
		finished := false
		last := time.Now()
		var res result
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()

		paint := func(done, failed, wait bool) {
			a := ui
			fyne.Do(func() { c.renderIdentity(a, done, failed, wait) })
		}

		fail := func(msg string) {
			a := ui
			fyne.Do(func() {
				c.setBusy(false)
				c.releaseEnrollForm()
				c.renderIdentity(a, false, true, false)
				c.show(uistate.Enroll)
				c.setEnrollFault(classifyEnrollError(msg))
			})
		}

		succeed := func() {
			fyne.Do(func() {
				c.setBusy(false)
				c.releaseEnrollForm()
				c.receipt = receiptFromEnroll(res.out, res.st)
				c.applyEnrolled(res.st, c.receipt)
				c.renderIdentity(n, true, false, false)
				c.refreshReceipt()
				c.token.SetText("")
			})
			time.Sleep(450 * time.Millisecond)
			fyne.Do(func() { c.show(uistate.Receipt) })
		}

		for {
			select {
			case r := <-doneCh:
				res = r
				if !enrollLooksSuccessful(res.out, res.err, res.st) {
					msg := strings.TrimSpace(res.out)
					if msg == "" && res.err != nil {
						msg = res.err.Error()
					}
					if msg == "" {
						msg = "Enrollment did not return a device certificate."
					}
					fail(msg)
					return
				}
				finished = true
				waiting = false
				target = n - 1
			case <-tick.C:
				if !finished {
					step := xdrclient.ReadEnrollProgress(platform.DataDir())
					if step != "" && step != "done" {
						if idx := identityStepIndex(step); idx > target {
							target = idx
							waiting = false
						}
					}
				}
				if waiting {
					continue
				}
				if ui < target && time.Since(last) >= identityStepHold {
					ui++
					last = time.Now()
					paint(false, false, false)
				}
				if finished && ui >= n-1 && time.Since(last) >= identityStepHold {
					succeed()
					return
				}
			}
		}
	}()
}
