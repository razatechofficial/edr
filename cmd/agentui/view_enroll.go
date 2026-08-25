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
	c.domain.SetPlaceHolder(apexSaaS)
	if saved := c.app.Preferences().String("enroll.domain"); saved != "" {
		c.domain.SetText(saved)
	}

	c.enrollFaultBox = container.NewVBox()

	c.enrollBtn = widget.NewButton("Enroll", c.onEnroll)
	c.enrollBtn.Importance = widget.HighImportance

	adv := container.NewVBox(
		caption("Management domain"),
		c.domain,
		bodyText(domainCaption()),
	)
	accordion := widget.NewAccordion(widget.NewAccordionItem(
		"Advanced — management domain (optional)",
		adv,
	))

	form := container.NewVBox(
		caption("Enrollment token"),
		c.token,
		accordion,
		c.enrollFaultBox,
	)

	header := pageHeader("First run", colorAccent, "Enroll this device", enrollBody())
	c.enrollContent = wizardPage(header, form, c.enrollBtn)
	return c.enrollContent
}

func (c *console) setEnrollFault(f uiFault) {
	c.enrollFaultBox.Objects = nil
	if f.Title != "" {
		c.enrollFaultBox.Add(faultCard(f))
	}
	c.enrollFaultBox.Refresh()
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
	c.show(uistate.Identity)
	c.startIdentity(host, tok)
}
