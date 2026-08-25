package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// Same frame as the native design lab (nativeTheme.width = 440, 8pt grid).
const (
	wizardW  float32 = 440
	wizardH  float32 = 640
	popoverW float32 = 336
	popoverH float32 = 500
)

func (c *console) lockSize(w, h float32) {
	c.win.SetFixedSize(false)
	c.win.Resize(fyne.NewSize(w, h))
	c.win.SetFixedSize(true)
}

func pageHeader(kick string, kickCol color.Color, title, body string) fyne.CanvasObject {
	items := []fyne.CanvasObject{
		kicker(kick, kickCol),
		heading(title),
	}
	if body != "" {
		items = append(items, bodyText(body))
	}
	return container.NewVBox(items...)
}

// wizardPage is a fixed sheet: header, filling body, pinned footer. No page scroll.
func wizardPage(header, body, footer fyne.CanvasObject) fyne.CanvasObject {
	top := container.NewPadded(header)
	var bot fyne.CanvasObject
	if footer != nil {
		bot = container.NewPadded(footer)
	}
	mid := container.NewPadded(body)
	return container.NewBorder(top, bot, nil, nil, mid)
}

func statusMark(state checkState) fyne.CanvasObject {
	slot := canvas.NewRectangle(color.Transparent)
	slot.SetMinSize(fyne.NewSize(22, 22))
	well := canvas.NewRectangle(colorInput)
	well.CornerRadius = 11
	well.SetMinSize(fyne.NewSize(22, 22))
	dot := canvas.NewRectangle(color.Transparent)
	dot.CornerRadius = 4
	dot.SetMinSize(fyne.NewSize(8, 8))
	switch state {
	case checkOK:
		well.FillColor = color.NRGBA{R: 0x30, G: 0xD1, B: 0x58, A: 0x28}
		dot.FillColor = colorOK
	case checkRun:
		well.FillColor = color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0x2E}
		dot.FillColor = colorAccent
	case checkFail:
		well.FillColor = color.NRGBA{R: 0xFF, G: 0x45, B: 0x3A, A: 0x28}
		dot.FillColor = colorDanger
	default:
		well.FillColor = colorInput
		dot.FillColor = color.Transparent
		dot.StrokeColor = colorMuted
		dot.StrokeWidth = 1.5
	}
	return container.NewCenter(container.NewStack(slot, well, container.NewCenter(dot)))
}

func listRow(mark fyne.CanvasObject, title, detail string, titleMuted bool) fyne.CanvasObject {
	t := widget.NewLabel(title)
	t.Wrapping = fyne.TextWrapWord
	if titleMuted {
		t.Importance = widget.LowImportance
	}
	if detail == "" {
		return container.NewBorder(nil, nil, mark, nil, t)
	}
	d := widget.NewLabel(detail)
	d.Wrapping = fyne.TextWrapWord
	d.Importance = widget.LowImportance
	return container.NewBorder(nil, nil, mark, nil, container.NewVBox(t, d))
}

func kvCell(label, value string) fyne.CanvasObject {
	l := caption(label)
	v := widget.NewLabel(value)
	v.Wrapping = fyne.TextWrapWord
	return container.NewVBox(l, v)
}
