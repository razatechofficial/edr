package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// TrayPopover.tsx — 8pt grid, 336px flyout.
const (
	dashW float32 = 336
	dashH float32 = 456

	dashHeaderPadT float32 = 20 // pt-5
	dashHeaderPadX float32 = 20 // px-5
	dashHeaderPadB float32 = 16 // pb-4
	dashHeroSize   float32 = 64 // h-16
	dashHeroGap    float32 = 16 // gap-4
	dashTitleSize  float32 = 26
	dashPillsMT    float32 = 10 // mt-2.5
	dashPillGap    float32 = 8  // gap-2
	dashPillPadY   float32 = 4  // py-1
	dashPillPadX   float32 = 10 // px-2.5
	dashPillMark   float32 = 6  // gap-1.5
	dashBannerMT   float32 = 16 // mt-4
	dashBannerPadX float32 = 12 // px-3
	dashBannerPadY float32 = 8  // py-2

	dashBodyPadX    float32 = 16 // px-4
	dashBodyPadY    float32 = 12 // pt-3 pb-3
	dashTileGap     float32 = 8  // gap-2
	dashTilePadX    float32 = 14 // px-3.5
	dashTilePadY    float32 = 12 // py-3
	dashNumMT       float32 = 4  // mt-1
	dashSparkMT     float32 = 8  // mt-2
	dashSparkH      float32 = 40
	dashHintMT      float32 = 6  // mt-1.5
	dashMetricsMT   float32 = 12 // mt-3
	dashMetricsPadY float32 = 12 // py-3
	dashMetricsPadX float32 = 4  // px-1
	dashIconWell    float32 = 28 // h-7
	dashMetricValMT float32 = 6  // mt-1.5

	dashFootPadX float32 = 20 // px-5
	dashFootPadY float32 = 10 // py-2.5
)

type padLayout struct {
	top, right, bottom, left float32
}

func (p padLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	min := fyne.NewSize(0, 0)
	if len(objects) > 0 && objects[0] != nil {
		min = objects[0].MinSize()
	}
	return fyne.NewSize(min.Width+p.left+p.right, min.Height+p.top+p.bottom)
}

func (p padLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) == 0 || objects[0] == nil {
		return
	}
	objects[0].Move(fyne.NewPos(p.left, p.top))
	objects[0].Resize(fyne.NewSize(
		size.Width-p.left-p.right,
		size.Height-p.top-p.bottom,
	))
}

func inset(top, right, bottom, left float32, obj fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&padLayout{top, right, bottom, left}, obj)
}

type stackAxis int

const (
	stackV stackAxis = iota
	stackH
)

type gapStack struct {
	axis stackAxis
	gap  float32
}

func visObjs(objects []fyne.CanvasObject) []fyne.CanvasObject {
	out := make([]fyne.CanvasObject, 0, len(objects))
	for _, o := range objects {
		if o != nil && o.Visible() {
			out = append(out, o)
		}
	}
	return out
}

func (s gapStack) MinSize(objects []fyne.CanvasObject) fyne.Size {
	vis := visObjs(objects)
	var w, h float32
	for i, o := range vis {
		m := o.MinSize()
		if s.axis == stackV {
			if m.Width > w {
				w = m.Width
			}
			h += m.Height
			if i > 0 {
				h += s.gap
			}
		} else {
			if m.Height > h {
				h = m.Height
			}
			w += m.Width
			if i > 0 {
				w += s.gap
			}
		}
	}
	return fyne.NewSize(w, h)
}

func (s gapStack) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		if o == nil || o.Visible() {
			continue
		}
		o.Resize(fyne.NewSize(0, 0))
	}
	vis := visObjs(objects)
	pos := float32(0)
	if s.axis == stackV {
		for _, o := range vis {
			m := o.MinSize()
			o.Move(fyne.NewPos(0, pos))
			o.Resize(fyne.NewSize(size.Width, m.Height))
			pos += m.Height + s.gap
		}
		return
	}
	for _, o := range vis {
		m := o.MinSize()
		o.Move(fyne.NewPos(pos, (size.Height-m.Height)/2))
		o.Resize(fyne.NewSize(m.Width, m.Height))
		pos += m.Width + s.gap
	}
}

func vstack(gap float32, objs ...fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&gapStack{axis: stackV, gap: gap}, objs...)
}

func hstack(gap float32, objs ...fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&gapStack{axis: stackH, gap: gap}, objs...)
}

type equalRow struct{ gap float32 }

func (e equalRow) MinSize(objects []fyne.CanvasObject) fyne.Size {
	vis := visObjs(objects)
	var h, w float32
	for i, o := range vis {
		m := o.MinSize()
		if m.Height > h {
			h = m.Height
		}
		w += m.Width
		if i > 0 {
			w += e.gap
		}
	}
	return fyne.NewSize(w, h)
}

func (e equalRow) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	vis := visObjs(objects)
	n := float32(len(vis))
	if n == 0 {
		return
	}
	cell := (size.Width - e.gap*(n-1)) / n
	x := float32(0)
	for _, o := range vis {
		o.Move(fyne.NewPos(x, 0))
		o.Resize(fyne.NewSize(cell, size.Height))
		x += cell + e.gap
	}
}

func splitRow(gap float32, objs ...fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&equalRow{gap: gap}, objs...)
}

// leadFill: 64px hero + gap-4 + title column that takes the rest (TrayPopover hero row).
type leadFill struct {
	leadW, gap float32
}

func (l leadFill) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) < 2 {
		return fyne.NewSize(0, 0)
	}
	a := objects[0].MinSize()
	b := objects[1].MinSize()
	h := a.Height
	if b.Height > h {
		h = b.Height
	}
	w := l.leadW
	if a.Width > w {
		w = a.Width
	}
	return fyne.NewSize(w+l.gap+b.Width, h)
}

func (l leadFill) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) < 2 {
		return
	}
	lead, rest := objects[0], objects[1]
	lh := lead.MinSize().Height
	lw := l.leadW
	lead.Move(fyne.NewPos(0, (size.Height-lh)/2))
	lead.Resize(fyne.NewSize(lw, lh))
	rest.Move(fyne.NewPos(lw+l.gap, 0))
	rest.Resize(fyne.NewSize(size.Width-lw-l.gap, size.Height))
}

func heroRow(icon, text fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&leadFill{leadW: dashHeroSize, gap: dashHeroGap}, icon, text)
}

// pinTopH keeps a short child (RAM bar) at the top of a 40px spark slot.
type pinTop struct{ h float32 }

func (p pinTop) MinSize(objects []fyne.CanvasObject) fyne.Size {
	w := float32(1)
	if len(objects) > 0 && objects[0] != nil {
		if m := objects[0].MinSize(); m.Width > w {
			w = m.Width
		}
	}
	return fyne.NewSize(w, p.h)
}

func (p pinTop) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) == 0 || objects[0] == nil {
		return
	}
	o := objects[0]
	h := o.MinSize().Height
	if h > size.Height {
		h = size.Height
	}
	o.Move(fyne.NewPos(0, 0))
	o.Resize(fyne.NewSize(size.Width, h))
}

func pinTopH(h float32, obj fyne.CanvasObject) fyne.CanvasObject {
	return container.New(&pinTop{h: h}, obj)
}

type metricsStrip struct{}

func (metricsStrip) MinSize(objects []fyne.CanvasObject) fyne.Size {
	var h float32
	for _, o := range objects {
		if o == nil || !o.Visible() {
			continue
		}
		if m := o.MinSize(); m.Height > h {
			h = m.Height
		}
	}
	return fyne.NewSize(80, h)
}

func (metricsStrip) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) < 5 {
		return
	}
	sepW := float32(1)
	col := (size.Width - sepW*2) / 3
	x := float32(0)
	place := func(o fyne.CanvasObject, w, yPad float32) {
		o.Move(fyne.NewPos(x, yPad))
		o.Resize(fyne.NewSize(w, size.Height-yPad*2))
		x += w
	}
	place(objects[0], col, 0)
	place(objects[1], sepW, 4)
	place(objects[2], col, 0)
	place(objects[3], sepW, 4)
	place(objects[4], col, 0)
}
