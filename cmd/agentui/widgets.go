package main

import (
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func card(obj fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorCard)
	bg.CornerRadius = 12
	return container.NewStack(bg, container.NewPadded(obj))
}

func accentCard(accent color.Color, obj fyne.CanvasObject) fyne.CanvasObject {
	bar := canvas.NewRectangle(accent)
	bar.SetMinSize(fyne.NewSize(4, 1))
	bg := canvas.NewRectangle(colorCard)
	bg.CornerRadius = 12
	inner := container.NewBorder(nil, nil, container.NewPadded(bar), nil, container.NewPadded(obj))
	return container.NewStack(bg, inner)
}

func caption(s string) *canvas.Text {
	t := canvas.NewText(s, colorMuted)
	t.TextSize = 11
	t.TextStyle = fyne.TextStyle{Monospace: true}
	return t
}

func heading(s string) *canvas.Text {
	t := canvas.NewText(s, colorText)
	t.TextSize = 22
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

func stepLabel(step, total int, title string) fyne.CanvasObject {
	chip := canvas.NewText(fmt.Sprintf("STEP %d OF %d", step, total), colorCyan)
	chip.TextSize = 11
	chip.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	h := heading(title)
	h.Alignment = fyne.TextAlignCenter
	return container.NewVBox(container.NewCenter(chip), container.NewCenter(h))
}

func (c *console) chrome(right fyne.CanvasObject) fyne.CanvasObject {
	mark := canvas.NewText("EDR AGENT", colorCyan)
	mark.TextSize = 14
	mark.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
	left := container.NewHBox(widget.NewIcon(c.app.Icon()), mark)
	if right == nil {
		right = layout.NewSpacer()
	}
	return container.NewBorder(nil, nil, left, right, layout.NewSpacer())
}

func (c *console) settingsButton() *widget.Button {
	btn := widget.NewButtonWithIcon("", theme.SettingsIcon(), c.showSettings)
	btn.Importance = widget.LowImportance
	return btn
}

func fieldWithIcon(icon fyne.Resource, entry fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorInput)
	bg.CornerRadius = 8
	ico := widget.NewIcon(icon)
	row := container.NewBorder(nil, nil, container.NewPadded(ico), nil, entry)
	return container.NewStack(bg, container.NewPadded(row))
}
