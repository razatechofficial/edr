package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildReceipt() fyne.CanvasObject {
	c.receiptBox = container.NewStack()
	c.receiptContinue = widget.NewButton("Continue", c.onReceiptContinue)
	c.receiptContinue.Importance = widget.HighImportance
	c.receiptContent = firstRunFrame(c.receiptBox)
	c.refreshReceipt()
	return c.receiptContent
}

func receiptField(label, value string, mono bool) fyne.CanvasObject {
	cap := labelCaps(label, 10, colorTertiary)
	v := canvas.NewText(dash(value), colorText)
	v.TextSize = 13
	if mono {
		v.TextStyle = fyne.TextStyle{Monospace: true}
	}
	return vstack(4, cap, v)
}

func (c *console) refreshReceipt() {
	r := c.receipt
	hero := heroWell(wizHero, colorOK, "check")
	kick := kicker("DEVICE ENROLLED", colorOK)
	title := heading("Identity bound")
	body := bodyText("The private key stayed on this computer. The signed certificate is this device’s identity.")
	head := iconBand(wizHero, wizHeroGap, hero, vstack(4, kick, title, gapH(6), body))

	fp := canvas.NewImageFromResource(drawMiniIcon("fingerprint", colorOK))
	fp.FillMode = canvas.ImageFillContain
	fp.SetMinSize(fyne.NewSize(14, 14))
	idCap := labelCaps("DEVICE ID", 10, colorTertiary)
	idVal := canvas.NewText(dash(r.DeviceID), colorText)
	idVal.TextSize = 20
	idVal.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	machCap := canvas.NewText("Machine ID", colorTertiary)
	machCap.TextSize = 11
	machVal := canvas.NewText(dash(r.MachineID), colorMuted)
	machVal.TextSize = 12
	machVal.TextStyle = fyne.TextStyle{Monospace: true}
	idBlock := inset(16, 16, 16, 16, vstack(0,
		hstack(8, fp, idCap),
		gapH(6),
		idVal,
		gapH(12),
		machCap,
		gapH(2),
		machVal,
	))

	fields := inset(14, 16, 14, 16, splitRow(16,
		vstack(14,
			receiptField("ISSUED BY", r.IssuedBy, false),
			receiptField("STORED IN", r.Storage, false),
		),
		vstack(14,
			receiptField("VALID UNTIL", r.ValidUntil, false),
			receiptField("ENROLLED", r.EnrolledAt, false),
		),
	))
	fieldRule := canvas.NewRectangle(color.NRGBA{R: 255, G: 255, B: 255, A: 0x0F})
	fieldRule.SetMinSize(fyne.NewSize(1, 1))

	sh := canvas.NewImageFromResource(drawMiniIcon("shield", colorOK))
	sh.FillMode = canvas.ImageFillContain
	sh.SetMinSize(fyne.NewSize(14, 14))
	footTxt := canvas.NewText("Keystore receipt · ingest host not shown", colorMuted)
	footTxt.TextSize = 11
	footBg := canvas.NewRectangle(color.NRGBA{R: 0, G: 0, B: 0, A: 0x2E})
	footInner := container.NewStack(footBg, inset(10, 16, 10, 16, hstack(8, sh, footTxt)))

	card := elevatedWell(16, vstack(0, idBlock, fieldRule, fields, footInner))
	caption := bodyText("Same fields as a Keychain or certificate-store receipt. Register already stored ingest.")

	c.receiptBox.Objects = []fyne.CanvasObject{pad5(vstack(0,
		head,
		gapH(20),
		card,
		gapH(12),
		caption,
		gapH(20),
		c.receiptContinue,
	))}
	c.receiptBox.Refresh()
}

func (c *console) onReceiptContinue() {
	if needsOSGrants() {
		c.show(uistate.Permissions)
		return
	}
	c.show(uistate.Preflight)
}
