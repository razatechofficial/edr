package main

import (
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
	"github.com/razatechofficial/edr/internal/platform"
	"github.com/razatechofficial/edr/internal/xdrclient"
)

func (c *console) buildIdentity() fyne.CanvasObject {
	c.identityBox = container.NewVBox()
	c.identityHint = widget.NewLabel("This device creates a key, sends a certificate request, and stores the signed cert in the OS keystore. The private key never leaves this computer.")
	c.identityHint.Wrapping = fyne.TextWrapWord

	lock := bodyText("Private key never leaves this device. Only the certificate request is sent.")

	body := container.NewVBox(
		c.chrome(),
		kicker("Enrolling", colorAccent),
		heading("Securing device identity"),
		c.identityHint,
		card(c.identityBox),
		card(lock),
	)
	c.identityContent = container.NewPadded(container.NewVScroll(body))
	return c.identityContent
}

func (c *console) renderIdentity(active int, done bool, failed bool) {
	c.identityBox.Objects = nil
	titles := identityTitles()
	for i, title := range titles {
		ico := theme.RadioButtonIcon()
		prefix := "○  "
		switch {
		case failed && i == active:
			ico = theme.ErrorIcon()
			prefix = "✕  "
		case done || i < active:
			ico = theme.ConfirmIcon()
			prefix = "✓  "
		case i == active:
			ico = theme.ViewRefreshIcon()
			prefix = "●  "
		}
		row := container.NewBorder(nil, nil, widget.NewIcon(ico), nil, widget.NewLabel(prefix+title))
		c.identityBox.Add(row)
	}
	if done {
		c.identityHint.SetText("Identity bound. Opening receipt…")
	}
	c.identityBox.Refresh()
}

func (c *console) startIdentity(host, token string) {
	titles := identityTitles()
	c.renderIdentity(0, false, false)
	c.identityHint.SetText("Enter an administrator password if the system asks. The private key never leaves this computer.")
	c.setBusy(true)
	xdrclient.ClearEnrollProgress(platform.DataDir())

	doneCh := make(chan struct {
		out string
		err error
		st  operatorStatus
	}, 1)
	go func() {
		out, err := runEdrctlPrivileged("enroll", "--host", host, "--token", token)
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
					c.last = res.st
					if res.err != nil && !res.st.Enrolled {
						msg := strings.TrimSpace(res.out)
						if msg == "" && res.err != nil {
							msg = res.err.Error()
						}
						c.renderIdentity(active, false, true)
						c.show(uistate.Enroll)
						c.setEnrollFault(classifyEnrollError(msg))
						return
					}
					c.renderIdentity(len(titles), true, false)
					c.receipt = receiptFromEnroll(res.out, res.st)
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
