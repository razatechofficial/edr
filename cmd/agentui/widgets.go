package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func card(obj fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorCard)
	bg.CornerRadius = 12
	return container.NewStack(bg, container.NewPadded(obj))
}

func caption(s string) *canvas.Text {
	t := canvas.NewText(s, colorMuted)
	t.TextSize = 11
	return t
}

func heading(s string) *canvas.Text {
	t := canvas.NewText(s, colorText)
	t.TextSize = 22
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

func kicker(s string, col color.Color) *canvas.Text {
	t := canvas.NewText(s, col)
	t.TextSize = 11
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

func bodyText(s string) *widget.Label {
	l := widget.NewLabel(s)
	l.Wrapping = fyne.TextWrapWord
	l.Importance = widget.LowImportance
	return l
}

func (c *console) chrome() fyne.CanvasObject {
	mark := canvas.NewText(productName, colorText)
	mark.TextSize = 14
	mark.TextStyle = fyne.TextStyle{Bold: true}
	ver := canvas.NewText("Version "+productVersion, colorMuted)
	ver.TextSize = 11
	return container.NewVBox(mark, ver)
}

func fieldWithIcon(icon fyne.Resource, entry fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorInput)
	bg.CornerRadius = 8
	ico := widget.NewIcon(icon)
	row := container.NewBorder(nil, nil, container.NewPadded(ico), nil, entry)
	return container.NewStack(bg, container.NewPadded(row))
}

func guideWell(text string) fyne.CanvasObject {
	if text == "" {
		return widget.NewLabel("")
	}
	bg := canvas.NewRectangle(color.NRGBA{R: 0xFF, G: 0x9F, B: 0x0A, A: 0x24})
	bg.CornerRadius = 8
	bg.StrokeColor = color.NRGBA{R: 0xFF, G: 0x9F, B: 0x0A, A: 0x33}
	bg.StrokeWidth = 1
	ico := canvas.NewImageFromResource(drawMiniIcon("alert", color.NRGBA{R: 0xFF, G: 0x9F, B: 0x0A, A: 0xFF}))
	ico.FillMode = canvas.ImageFillContain
	ico.SetMinSize(fyne.NewSize(16, 16))
	body := widget.NewLabel(text)
	body.Wrapping = fyne.TextWrapWord
	row := container.NewBorder(nil, nil, container.NewPadded(ico), nil, body)
	return container.NewStack(bg, container.NewPadded(row))
}

func faultCard(f uiFault) fyne.CanvasObject {
	if f.Title == "" {
		return widget.NewLabel("")
	}
	title := widget.NewLabelWithStyle(f.Title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	title.Wrapping = fyne.TextWrapWord
	body := widget.NewLabel(f.Body)
	body.Wrapping = fyne.TextWrapWord
	detail := widget.NewLabel(f.Detail)
	detail.Wrapping = fyne.TextWrapWord
	detail.Importance = widget.LowImportance
	items := []fyne.CanvasObject{title, body, detail}
	if f.Action != "" {
		if f.OnAction != nil {
			btn := widget.NewButton(f.Action, f.OnAction)
			btn.Importance = widget.MediumImportance
			items = append(items, btn)
		} else {
			act := caption(f.Action)
			items = append(items, act)
		}
	}
	bg := canvas.NewRectangle(color.NRGBA{R: 0xFF, G: 0x45, B: 0x3A, A: 0x24})
	bg.CornerRadius = 12
	return container.NewStack(bg, container.NewPadded(container.NewVBox(items...)))
}
