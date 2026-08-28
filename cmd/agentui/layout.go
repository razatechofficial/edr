package main

import (
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/razatechofficial/edr/cmd/agentui/uistate"
)

// Same frame as the native design lab (nativeTheme.width = 440, 8pt grid).
const (
	wizardW  float32 = 440
	wizardH  float32 = 540
	popoverW float32 = dashW
	popoverH float32 = dashH
)

func wizardHeight(id uistate.Screen) float32 {
	switch id {
	case uistate.Identity:
		return 580
	case uistate.Receipt:
		return 620
	case uistate.Permissions:
		return 540
	case uistate.Preflight:
		return 520
	case uistate.Setup:
		return 640
	case uistate.Enroll:
		return 360
	default:
		return wizardH
	}
}

func (c *console) lockSize(w, h float32) {
	if c.win == nil {
		return
	}
	want := fyne.NewSize(w, h)
	if c.win.Content() != nil {
		got := c.win.Canvas().Size()
		if abs32(got.Width-want.Width) < 1 && abs32(got.Height-want.Height) < 1 {
			return
		}
	}
	nativeResizeKeepTop(c.win, w, h)
	c.win.Resize(want)
}

func abs32(v float32) float32 {
	if v < 0 {
		return -v
	}
	return v
}

func clampEnrollH(h float32) float32 {
	if h < 1 {
		h = 280
	}
	if h > 640 {
		h = 640
	}
	return h
}

func (c *console) fitEnroll() {
	if c.win == nil || c.enrollContent == nil {
		return
	}
	c.lockSize(wizardW, clampEnrollH(c.enrollContent.MinSize().Height))
}

func pageHeader(kick string, kickCol color.Color, title, body string) fyne.CanvasObject {
	items := []fyne.CanvasObject{
		kicker(kick, kickCol),
		heading(title),
	}
	if body != "" {
		items = append(items, bodyText(body))
	}
	return vstack(8, items...)
}

func osBadgeLabel() string {
	switch {
	case isDarwin():
		return "macOS"
	case isWindows():
		return "Windows"
	default:
		return "Linux"
	}
}

func productHeader() fyne.CanvasObject {
	well := canvas.NewRectangle(color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0x2E})
	well.CornerRadius = 10
	well.SetMinSize(fyne.NewSize(40, 40))
	ico := canvas.NewImageFromResource(heroResource(colorAccent, heroOK))
	ico.FillMode = canvas.ImageFillContain
	ico.SetMinSize(fyne.NewSize(40, 40))
	mark := canvas.NewText(productName, colorText)
	mark.TextSize = 17
	mark.TextStyle = fyne.TextStyle{Bold: true}
	ver := canvas.NewText("Version "+productVersion, colorMuted)
	ver.TextSize = 13
	badgeTxt := canvas.NewText(osBadgeLabel(), colorMuted)
	badgeTxt.TextSize = 11
	badgeBg := canvas.NewRectangle(color.Transparent)
	badgeBg.StrokeColor = colorSep
	badgeBg.StrokeWidth = 1
	badgeBg.CornerRadius = 6
	badge := container.NewStack(badgeBg, inset(4, 8, 4, 8, badgeTxt))
	row := container.NewBorder(nil, nil,
		container.NewCenter(container.NewStack(well, ico)),
		badge,
		inset(0, 12, 0, 12, vstack(0, mark, ver)),
	)
	rule := canvas.NewRectangle(colorHairline)
	rule.SetMinSize(fyne.NewSize(1, 1))
	return vstack(0, inset(20, 20, 20, 20, row), rule)
}

func statusMark(state checkState) fyne.CanvasObject {
	well := canvas.NewRectangle(colorInput)
	well.CornerRadius = 14
	well.SetMinSize(fyne.NewSize(28, 28))
	var glyph fyne.CanvasObject
	switch state {
	case checkOK:
		well.FillColor = color.NRGBA{R: 0x30, G: 0xD1, B: 0x58, A: 0x29}
		img := canvas.NewImageFromResource(drawMiniIcon("check", color.NRGBA{R: 0x30, G: 0xD1, B: 0x58, A: 0xFF}))
		img.FillMode = canvas.ImageFillContain
		img.SetMinSize(fyne.NewSize(14, 14))
		glyph = img
	case checkRun:
		well.FillColor = color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0x2E}
		glyph = newRadialSpin()
	case checkFail:
		well.FillColor = color.NRGBA{R: 0xFF, G: 0x45, B: 0x3A, A: 0x28}
		img := canvas.NewImageFromResource(drawMiniIcon("alert", colorDanger))
		img.FillMode = canvas.ImageFillContain
		img.SetMinSize(fyne.NewSize(14, 14))
		glyph = img
	default:
		well.FillColor = colorInput
		ring := canvas.NewCircle(color.Transparent)
		ring.StrokeColor = colorTertiary
		ring.StrokeWidth = 2
		glyph = ring
	}
	return container.New(&iconWellLay{well: 28, glyph: 14}, well, glyph)
}

type iconWellLay struct{ well, glyph float32 }

func (l iconWellLay) MinSize([]fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(l.well, l.well)
}

func (l iconWellLay) Layout(objects []fyne.CanvasObject, _ fyne.Size) {
	if len(objects) == 0 {
		return
	}
	objects[0].Move(fyne.NewPos(0, 0))
	objects[0].Resize(fyne.NewSize(l.well, l.well))
	if len(objects) < 2 || objects[1] == nil {
		return
	}
	p := (l.well - l.glyph) / 2
	objects[1].Move(fyne.NewPos(p, p))
	objects[1].Resize(fyne.NewSize(l.glyph, l.glyph))
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

func compactTitle(s string, muted bool) *canvas.Text {
	col := colorText
	if muted {
		col = colorMuted
	}
	t := canvas.NewText(s, col)
	t.TextSize = 13
	return t
}

type radialSpin struct {
	widget.BaseWidget
	img  *canvas.Image
	anim *fyne.Animation
}

func newRadialSpin() *radialSpin {
	s := &radialSpin{}
	s.ExtendBaseWidget(s)
	s.img = canvas.NewImageFromResource(drawSpinnerPhase(0))
	s.img.FillMode = canvas.ImageFillContain
	s.img.SetMinSize(fyne.NewSize(14, 14))
	s.anim = fyne.NewAnimation(800*time.Millisecond, func(done float32) {
		ph := int(done*8) % 8
		s.img.Resource = drawSpinnerPhase(ph)
		s.img.Refresh()
	})
	s.anim.RepeatCount = fyne.AnimationRepeatForever
	s.anim.Curve = fyne.AnimationLinear
	s.anim.Start()
	return s
}

func (s *radialSpin) CreateRenderer() fyne.WidgetRenderer {
	return &spinRender{s: s, objs: []fyne.CanvasObject{s.img}}
}

type spinRender struct {
	s    *radialSpin
	objs []fyne.CanvasObject
}

func (r *spinRender) Destroy() {
	if r.s != nil && r.s.anim != nil {
		r.s.anim.Stop()
	}
}

func (r *spinRender) Layout(sz fyne.Size) {
	if len(r.objs) == 0 {
		return
	}
	const g float32 = 14
	r.objs[0].Resize(fyne.NewSize(g, g))
	r.objs[0].Move(fyne.NewPos((sz.Width-g)/2, (sz.Height-g)/2))
}

func (r *spinRender) MinSize() fyne.Size { return fyne.NewSize(14, 14) }

func (r *spinRender) Objects() []fyne.CanvasObject { return r.objs }

func (r *spinRender) Refresh() {
	for _, o := range r.objs {
		o.Refresh()
	}
}
