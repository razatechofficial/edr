package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

func (c *console) buildPermissions() fyne.CanvasObject {
	c.permHint = widget.NewLabel(permBody())
	c.permHint.Wrapping = fyne.TextWrapWord

	c.grantBtn = widget.NewButton(openSettingsLabel(), func() {
		_ = openOSGrantSettings()
		c.permHint.SetText("Open the system pane, grant access, then Recheck. Do not skip.")
	})
	c.grantBtn.Importance = widget.MediumImportance
	c.permFaultBox = container.NewVBox()

	recheck := widget.NewButton("Recheck", func() {
		if needsOSGrants() {
			c.permHint.SetText("Required OS access is still missing. Grant access, then Recheck.")
			c.permFaultBox.Objects = nil
			c.permFaultBox.Add(faultCard(uiFault{
				Title:  "Required OS access was removed",
				Body:   "The sensor is limited until access is restored. Recheck after you change the setting.",
				Detail: permGuide(),
				Action: openSettingsLabel(),
			}))
			c.permFaultBox.Refresh()
			return
		}
		c.permFaultBox.Objects = nil
		c.permFaultBox.Refresh()
		c.show(uistate.Preflight)
	})
	recheck.Importance = widget.HighImportance

	header := pageHeader("Required access", colorWarn, "Grant OS access", "")
	header = container.NewVBox(header, c.permHint)
	body := container.NewVBox(card(bodyText(permGuide())), c.permFaultBox)
	foot := container.NewGridWithColumns(2, c.grantBtn, recheck)
	c.permContent = wizardPage(header, body, foot)
	return c.permContent
}

func permGuide() string {
	switch {
	case isDarwin():
		return "System Settings → Privacy & Security: System Extension, Full Disk Access, and network filter. Then Recheck."
	case isWindows():
		return "Allow EDR Agent through Windows Defender Firewall if prompted. Then Recheck."
	default:
		return "Restore CAP_SYS_ADMIN / audit capabilities your packager set, then retry Start."
	}
}

func needsOSGrants() bool {
	return needsFullDiskAccess() && !hasFullDiskAccess()
}
