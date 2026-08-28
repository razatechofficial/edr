package main

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildEnroll() fyne.CanvasObject {
	c.token = widget.NewPasswordEntry()
	c.token.SetPlaceHolder("Paste token from the console")

	c.domain = widget.NewEntry()
	c.domain.SetPlaceHolder("xdr.example.com")
	if saved := c.app.Preferences().String("enroll.domain"); saved != "" {
		c.domain.SetText(saved)
	}

	c.enrollFaultBox = container.NewVBox()
	c.enrollFaultBox.Hide()
	c.enrollAdvOpen = false

	c.enrollBtn = widget.NewButton("Enroll", c.onEnroll)
	c.enrollBtn.Importance = widget.HighImportance

	c.enrollAdv = vstack(0,
		gapH(12),
		nativeLabel("Management domain"),
		gapH(8),
		inputShell(c.domain),
		gapH(8),
		domainCaptionRich(),
	)
	c.enrollAdv.Hide()

	c.enrollAdvLink = newTextLink("Advanced — management domain (optional)", c.toggleEnrollAdvanced)

	form := pad5(vstack(0,
		heading("Enroll this device"),
		gapH(8),
		enrollBodyRich(),
		gapH(20),
		nativeLabel("Enrollment token"),
		gapH(8),
		inputShell(c.token),
		gapH(16),
		c.enrollAdvLink,
		c.enrollAdv,
		c.enrollFaultBox,
		gapH(16),
		c.enrollBtn,
	))
	c.enrollContent = firstRunFrame(form)
	return c.enrollContent
}

func (c *console) toggleEnrollAdvanced() {
	opening := !c.enrollAdvOpen
	c.enrollAdvOpen = opening
	if c.enrollAdvLink != nil {
		c.enrollAdvLink.SetOpen(opening)
	}
	if opening {
		// Grow the window before revealing fields so layout does not clip then jump.
		if c.screen == uistate.Enroll && c.enrollContent != nil && c.enrollAdv != nil {
			h := c.enrollContent.MinSize().Height + c.enrollAdv.MinSize().Height
			c.lockSize(wizardW, clampEnrollH(h))
		}
		c.enrollAdv.Show()
		return
	}
	c.enrollAdv.Hide()
	if c.screen == uistate.Enroll {
		c.fitEnroll()
	}
}

func (c *console) setEnrollFault(f uiFault) {
	c.enrollFaultBox.Objects = nil
	if f.Title != "" {
		c.enrollFaultBox.Add(gapH(12))
		c.enrollFaultBox.Add(faultCard(f))
		c.enrollFaultBox.Show()
	} else {
		c.enrollFaultBox.Hide()
	}
	c.enrollFaultBox.Refresh()
	if c.screen == uistate.Enroll {
		c.fitEnroll()
	}
}

func (c *console) lockEnrollForm() {
	if c.token != nil {
		c.token.Disable()
	}
	if c.domain != nil {
		c.domain.Disable()
	}
	if c.enrollBtn != nil {
		c.enrollBtn.SetText("Enrolling…")
	}
}

func (c *console) releaseEnrollForm() {
	if c.token != nil {
		c.token.Enable()
	}
	if c.domain != nil {
		c.domain.Enable()
	}
	if c.enrollBtn != nil {
		c.enrollBtn.SetText("Enroll")
	}
}

func (c *console) onEnroll() {
	if c.busy {
		return
	}
	tok := strings.TrimSpace(c.token.Text)
	if tok == "" {
		c.setEnrollFault(faultTokenMissing())
		return
	}
	apex := strings.TrimSpace(c.domain.Text)
	if domainLooksInvalid(apex) {
		c.setEnrollFault(faultDomainInvalid())
		return
	}
	host := enrollmentHostFromDomain(apex)
	c.app.Preferences().SetString("enroll.domain", apex)
	c.setEnrollFault(uiFault{})
	c.lockEnrollForm()
	c.setBusy(true)
	c.show(uistate.Identity)
	c.startIdentity(host, tok)
}
