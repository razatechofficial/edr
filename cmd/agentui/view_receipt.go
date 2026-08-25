package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildReceipt() fyne.CanvasObject {
	c.receiptBox = container.NewVBox()
	c.receiptContinue = widget.NewButton("Continue", c.onReceiptContinue)
	c.receiptContinue.Importance = widget.HighImportance

	body := container.NewVBox(
		c.chrome(),
		kicker("Device enrolled", colorOK),
		heading("Identity bound"),
		bodyText("The private key stayed on this computer. The signed certificate is this device’s identity."),
		card(c.receiptBox),
		bodyText("Same fields as a Keychain or certificate-store receipt. Register already stored ingest."),
		c.receiptContinue,
	)
	c.receiptContent = container.NewPadded(container.NewVScroll(body))
	return c.receiptContent
}

func receiptRow(label, value string) fyne.CanvasObject {
	l := caption(label)
	v := widget.NewLabel(value)
	v.Wrapping = fyne.TextWrapWord
	return container.NewVBox(l, v)
}

func (c *console) refreshReceipt() {
	r := c.receipt
	c.receiptBox.Objects = nil
	c.receiptBox.Add(receiptRow("Device ID", dash(r.DeviceID)))
	c.receiptBox.Add(receiptRow("Machine ID", dash(r.MachineID)))
	c.receiptBox.Add(receiptRow("Issued by", dash(r.IssuedBy)))
	c.receiptBox.Add(receiptRow("Valid until", dash(r.ValidUntil)))
	c.receiptBox.Add(receiptRow("Stored in", dash(r.Storage)))
	c.receiptBox.Add(receiptRow("Enrolled", dash(r.EnrolledAt)))
	c.receiptBox.Add(caption("Keystore receipt · ingest host not shown"))
	c.receiptBox.Refresh()
}

func (c *console) onReceiptContinue() {
	if needsOSGrants() {
		c.show(uistate.Permissions)
		return
	}
	c.show(uistate.Preflight)
}
