package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
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

// inputShell matches NativeInput: 36px tall, 12px inner padding from the theme.
func inputShell(e *widget.Entry) fyne.CanvasObject {
	slot := canvas.NewRectangle(color.Transparent)
	slot.SetMinSize(fyne.NewSize(1, 36))
	return container.NewStack(slot, e)
}

// textLink is a disclosure control: chevron + muted label, pointer, accent on hover.
type textLink struct {
	widget.BaseWidget
	text    string
	hovered bool
	open    bool
	onTap   func()
}

func newTextLink(text string, onTap func()) *textLink {
	l := &textLink{text: text, onTap: onTap}
	l.ExtendBaseWidget(l)
	return l
}

func (l *textLink) SetOpen(open bool) {
	if l.open == open {
		return
	}
	l.open = open
	l.Refresh()
}

func (l *textLink) Tapped(_ *fyne.PointEvent) {
	if l.onTap != nil {
		l.onTap()
	}
}

func (l *textLink) MouseIn(_ *desktop.MouseEvent) {
	l.hovered = true
	l.Refresh()
}

func (l *textLink) MouseMoved(_ *desktop.MouseEvent) {}

func (l *textLink) MouseOut() {
	l.hovered = false
	l.Refresh()
}

func (l *textLink) Cursor() desktop.Cursor {
	return desktop.PointerCursor
}

func (l *textLink) CreateRenderer() fyne.WidgetRenderer {
	ico := canvas.NewImageFromResource(drawMiniIcon("chevron-right", colorMuted))
	ico.FillMode = canvas.ImageFillContain
	ico.SetMinSize(fyne.NewSize(12, 12))
	t := canvas.NewText(l.text, colorMuted)
	t.TextSize = 13
	t.TextStyle = fyne.TextStyle{Bold: true}
	r := &textLinkRender{l: l, ico: ico, t: t}
	r.Refresh()
	return r
}

type textLinkRender struct {
	l   *textLink
	ico *canvas.Image
	t   *canvas.Text
}

func (r *textLinkRender) Destroy() {}

func (r *textLinkRender) Layout(sz fyne.Size) {
	r.ico.Resize(fyne.NewSize(12, 12))
	r.ico.Move(fyne.NewPos(0, (sz.Height-12)/2))
	m := r.t.MinSize()
	r.t.Move(fyne.NewPos(18, (sz.Height-m.Height)/2))
	r.t.Resize(m)
}

func (r *textLinkRender) MinSize() fyne.Size {
	m := r.t.MinSize()
	h := m.Height
	if h < 20 {
		h = 20
	}
	return fyne.NewSize(18+m.Width, h)
}

func (r *textLinkRender) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.ico, r.t}
}

func (r *textLinkRender) Refresh() {
	col := colorMuted
	if r.l.hovered {
		col = colorAccentHover
	}
	kind := "chevron-right"
	if r.l.open {
		kind = "chevron-down"
	}
	r.ico.Resource = drawMiniIcon(kind, col)
	r.ico.Refresh()
	r.t.Text = r.l.text
	r.t.Color = col
	r.t.Refresh()
}

var (
	_ fyne.Tappable      = (*textLink)(nil)
	_ desktop.Hoverable  = (*textLink)(nil)
	_ desktop.Cursorable = (*textLink)(nil)
)

func mutedSeg(s string) *widget.TextSegment {
	return &widget.TextSegment{
		Text: s,
		Style: widget.RichTextStyle{
			Inline:    true,
			ColorName: theme.ColorNameDisabled,
			SizeName:  theme.SizeNameText,
		},
	}
}

func domainSeg(s string) *widget.TextSegment {
	return &widget.TextSegment{
		Text: s,
		Style: widget.RichTextStyle{
			Inline:    true,
			ColorName: theme.ColorNamePrimary,
			SizeName:  theme.SizeNameText,
			TextStyle: fyne.TextStyle{Bold: true},
		},
	}
}

func captionSeg(s string) *widget.TextSegment {
	return &widget.TextSegment{
		Text: s,
		Style: widget.RichTextStyle{
			Inline:    true,
			ColorName: theme.ColorNameDisabled,
			SizeName:  theme.SizeNameCaptionText,
		},
	}
}

func domainCaptionSeg(s string) *widget.TextSegment {
	return &widget.TextSegment{
		Text: s,
		Style: widget.RichTextStyle{
			Inline:    true,
			ColorName: theme.ColorNamePrimary,
			SizeName:  theme.SizeNameCaptionText,
			TextStyle: fyne.TextStyle{Bold: true},
		},
	}
}

func enrollBodyRich() fyne.CanvasObject {
	r := widget.NewRichText(
		mutedSeg("Paste the one-time token from the console. Leave the management domain blank to use the default "),
		domainSeg(apexSaaS),
		mutedSeg("."),
	)
	r.Wrapping = fyne.TextWrapWord
	r.Scroll = container.ScrollNone
	return r
}

func domainCaptionRich() fyne.CanvasObject {
	r := widget.NewRichText(
		captionSeg("Leave blank to use the default "),
		domainCaptionSeg(apexSaaS),
		captionSeg("."),
	)
	r.Wrapping = fyne.TextWrapWord
	r.Scroll = container.ScrollNone
	return r
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
	row := iconBand(16, 8, ico, body)
	return container.NewStack(bg, inset(10, 12, 10, 12, row))
}

func faultCard(f uiFault) fyne.CanvasObject {
	if f.Title == "" {
		return widget.NewLabel("")
	}
	title := canvas.NewText(f.Title, colorText)
	title.TextSize = 13
	title.TextStyle = fyne.TextStyle{Bold: true}
	body := widget.NewLabel(f.Body)
	body.Wrapping = fyne.TextWrapWord
	detail := widget.NewLabel(f.Detail)
	detail.Wrapping = fyne.TextWrapWord
	detail.Importance = widget.LowImportance
	items := []fyne.CanvasObject{title, gapH(4), body, gapH(4), detail}
	if f.Action != "" && f.OnAction != nil {
		btn := widget.NewButton(f.Action, f.OnAction)
		btn.Importance = widget.HighImportance
		items = append(items, gapH(12), btn)
	}
	bg := canvas.NewRectangle(color.NRGBA{R: 0xFF, G: 0x45, B: 0x3A, A: 0x24})
	bg.CornerRadius = 12
	bg.StrokeColor = color.NRGBA{R: 0xFF, G: 0x45, B: 0x3A, A: 0x66}
	bg.StrokeWidth = 1
	return container.NewStack(bg, inset(12, 14, 12, 14, vstack(0, items...)))
}
