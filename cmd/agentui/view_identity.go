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

	hero := canvas.NewImageFromResource(heroResource(colorAccent, heroOK))
	hero.FillMode = canvas.ImageFillContain
	hero.SetMinSize(fyne.NewSize(56, 56))
	kick := kicker("ENROLLING", colorAccent)
	title := heading("Securing device identity")
	header := container.NewVBox(
		container.NewBorder(nil, nil, hero, nil, container.NewPadded(container.NewVBox(kick, title))),
		c.identityHint,
	)

	c.identityBar = widget.NewProgressBar()
	c.identityBar.Min = 0
	c.identityBar.Max = 1
	c.identityBar.TextFormatter = func() string { return "" }
	c.identityCount = canvas.NewText("0/7", colorTertiary)
	c.identityCount.TextSize = 11
	c.identityDoing = canvas.NewText("Validating the enrollment token…", colorMuted)
	c.identityDoing.TextSize = 12

	c.identityBox = container.NewVBox()
	meter := container.NewBorder(nil, nil, nil, c.identityCount, c.identityBar)
	body := container.NewVBox(meter, c.identityDoing, c.identityBox)

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
	lock := container.NewStack(lockBg, container.NewPadded(
		container.NewBorder(nil, nil, container.NewPadded(lockIco), nil, lockTxt),
	))

	c.identityContent = wizardPage(header, body, lock)
	return c.identityContent
}

func (c *console) renderIdentity(active int, done bool, failed bool) {
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
		row := container.NewPadded(container.NewBorder(nil, nil, statusMark(st), nil, compactTitle(title, st == checkWait || st == checkOK)))
		c.identityBox.Add(row)
	}
	frac := float64(passed) / float64(n)
	if !done && !failed && active < n {
		frac = (float64(passed) + 0.45) / float64(n)
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
		default:
			c.identityDoing.Text = identityDoing(active)
			c.identityDoing.Color = colorMuted
		}
		c.identityDoing.Refresh()
	}
	c.identityBox.Refresh()
}

func (c *console) startIdentity(host, token string) {
	titles := identityTitles()
	c.renderIdentity(0, false, false)
	c.setBusy(true)
	xdrclient.ClearEnrollProgress(platform.DataDir())

	doneCh := make(chan struct {
		out string
		err error
		st  operatorStatus
	}, 1)
	go func() {
		out, err := runEdrctlPrivileged("enroll", "--force", "--host", host, "--token", token)
		st := loadStatus()
		doneCh <- struct {
			out string
			err error
			st  operatorStatus
		}{out, err, st}
	}()

	go func() {
		active := 0
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case res := <-doneCh:
				fyne.Do(func() {
					c.setBusy(false)
					if !enrollLooksSuccessful(res.out, res.err, res.st) {
						msg := strings.TrimSpace(res.out)
						if msg == "" && res.err != nil {
							msg = res.err.Error()
						}
						if msg == "" {
							msg = "Enrollment did not return a device certificate."
						}
						c.renderIdentity(active, false, true)
						c.show(uistate.Enroll)
						c.setEnrollFault(classifyEnrollError(msg))
						return
					}
					c.receipt = receiptFromEnroll(res.out, res.st)
					c.applyEnrolled(res.st, c.receipt)
					c.renderIdentity(len(titles), true, false)
					c.refreshReceipt()
					c.token.SetText("")
					c.show(uistate.Receipt)
				})
				return
			case <-tick.C:
				if step := xdrclient.ReadEnrollProgress(platform.DataDir()); step != "" {
					if idx := identityStepIndex(step); idx > active {
						active = idx
						a := active
						fyne.Do(func() { c.renderIdentity(a, false, false) })
					}
				}
			}
		}
	}()
}
