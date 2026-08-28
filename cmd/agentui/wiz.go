package main

import (
	"image"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// NativeInstallerMock / AgentDesktopMock — nativeTheme 8pt grid.
const (
	wizPad     float32 = 20 // px-5 py-5
	wizPad2    float32 = 8  // mt-2 / py-2
	wizPad3    float32 = 12 // mt-3 / gap-3
	wizPad4    float32 = 16 // mt-4 / py-4
	wizPad5    float32 = 20 // mt-5
	wizPad6    float32 = 24 // mt-6
	wizPad8    float32 = 32 // py-8
	wizEulaH   float32 = 176
	wizHero    float32 = 56 // h-14
	wizHeroGap float32 = 14 // gap-3.5
	wizMark    float32 = 28
)

func pad5(obj fyne.CanvasObject) fyne.CanvasObject {
	return inset(wizPad, wizPad, wizPad, wizPad, obj)
}

func hairline() *canvas.Rectangle {
	r := canvas.NewRectangle(colorHairline)
	r.SetMinSize(fyne.NewSize(1, 1))
	return r
}

func installerFrame(body fyne.CanvasObject) fyne.CanvasObject {
	return vstack(0, productHeader(), body)
}

func firstRunFrame(body fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&shadeStack{}, newGlowBG(colorAccent), body)
}

// shadeStack paints a wash behind content without inflating MinSize.
type shadeStack struct{}

func (shadeStack) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) < 2 || objects[1] == nil {
		return fyne.NewSize(0, 0)
	}
	return objects[1].MinSize()
}

func (shadeStack) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		if o == nil {
			continue
		}
		o.Move(fyne.NewPos(0, 0))
		o.Resize(size)
	}
}

func iconBand(size, gap float32, icon, text fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&leadFill{leadW: size, gap: gap}, icon, text)
}

func elevatedWell(radius float32, inner fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(colorCard)
	bg.CornerRadius = radius
	bg.StrokeColor = colorSep
	bg.StrokeWidth = 1
	return container.NewStack(bg, inner)
}

func checkRow(mark fyne.CanvasObject, title, badge string, st checkState) fyne.CanvasObject {
	col := colorMuted
	switch st {
	case checkOK:
		col = colorTertiary
	case checkRun, checkFail:
		col = colorText
	}
	t := canvas.NewText(title, col)
	t.TextSize = 13
	head := fyne.CanvasObject(t)
	if badge != "" {
		b := canvas.NewText(badge, colorWarn)
		b.TextSize = 11
		b.TextStyle = fyne.TextStyle{Bold: true}
		head = container.NewBorder(nil, nil, nil, b, t)
	}
	return inset(8, 0, 8, 0, iconBand(wizMark, wizPad3, mark, head))
}

// timelineRow matches IdentityProgress: 28px StatusIcon, 12px gap, text pt-1.
func timelineRow(st checkState, title string, last, passedLine bool) fyne.CanvasObject {
	col := colorMuted
	switch st {
	case checkOK:
		col = colorTertiary
	case checkRun, checkFail:
		col = colorText
	}
	t := canvas.NewText(title, col)
	t.TextSize = 13
	t.TextStyle = fyne.TextStyle{Bold: true}
	line := canvas.NewRectangle(colorSep)
	if passedLine {
		line.FillColor = color.NRGBA{R: 0x30, G: 0xD1, B: 0x58, A: 0x55}
	}
	line.SetMinSize(fyne.NewSize(1, 8))
	if last {
		line.Hide()
	}
	return container.New(&timelineLay{last: last}, statusMark(st), line, t)
}

type timelineLay struct{ last bool }

func (t timelineLay) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) < 3 {
		return fyne.NewSize(0, 0)
	}
	th := objects[2].MinSize()
	h := float32(40) // 28px mark + 12px pb-3
	if th.Height+16 > h {
		h = th.Height + 16
	}
	return fyne.NewSize(28+12+th.Width, h)
}

func (t timelineLay) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) < 3 {
		return
	}
	mark, line, title := objects[0], objects[1], objects[2]
	mark.Move(fyne.NewPos(0, 0))
	mark.Resize(fyne.NewSize(28, 28))
	tm := title.MinSize()
	title.Move(fyne.NewPos(40, 5))
	title.Resize(tm)
	if t.last || !line.Visible() {
		line.Resize(fyne.NewSize(0, 0))
		return
	}
	line.Move(fyne.NewPos(13, 32))
	lh := size.Height - 32
	if lh < 4 {
		lh = 4
	}
	line.Resize(fyne.NewSize(1, lh))
}

func checklistFooter(objs ...fyne.CanvasObject) fyne.CanvasObject {
	return vstack(0, hairline(), inset(wizPad4, wizPad, wizPad4, wizPad, vstack(wizPad3, objs...)))
}

func checklistSheet(intro, list, foot fyne.CanvasObject) fyne.CanvasObject {
	top := intro
	if top == nil {
		top = canvas.NewRectangle(color.Transparent)
	}
	// Pack intro + rows at the top so leftover height sits above the footer,
	// not between checklist items.
	return container.NewBorder(nil, foot, nil, nil, vstack(0, top, list))
}

func heroWell(size float32, tone color.NRGBA, kind string) fyne.CanvasObject {
	bg := canvas.NewRaster(func(w, h int) image.Image {
		return drawHeroWell(w, h, tone)
	})
	bg.SetMinSize(fyne.NewSize(size, size))
	img := canvas.NewImageFromResource(drawMiniIcon(kind, tone))
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(28, 28))
	return container.New(&iconWellLay{well: size, glyph: 28}, bg, img)
}

func nativeLabel(s string) *canvas.Text {
	t := canvas.NewText(s, colorMuted)
	t.TextSize = 13
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

func processLine(s string) *widget.Label {
	l := widget.NewLabel(s)
	l.Wrapping = fyne.TextWrapWord
	return l
}
