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

	header := pageHeader("Device enrolled", colorOK, "Identity bound",
		"The private key stayed on this computer. The signed certificate is this device’s identity.")
	foot := container.NewVBox(
		bodyText("Same fields as a Keychain or certificate-store receipt. Register already stored ingest."),
		c.receiptContinue,
	)
	c.receiptContent = wizardPage(header, card(c.receiptBox), foot)
	return c.receiptContent
}

func (c *console) refreshReceipt() {
	r := c.receipt
	c.receiptBox.Objects = nil
	id := widget.NewLabel(dash(r.DeviceID))
	id.Wrapping = fyne.TextWrapWord
	id.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
	c.receiptBox.Add(caption("Device ID"))
	c.receiptBox.Add(id)
	c.receiptBox.Add(kvCell("Machine ID", dash(r.MachineID)))
	c.receiptBox.Add(container.NewGridWithColumns(2,
		kvCell("Issued by", dash(r.IssuedBy)),
		kvCell("Valid until", dash(r.ValidUntil)),
		kvCell("Stored in", dash(r.Storage)),
		kvCell("Enrolled", dash(r.EnrolledAt)),
	))
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
