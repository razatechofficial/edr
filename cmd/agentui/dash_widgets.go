package main

import (
	"image"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

const (
	liveDotBox  float32 = 16
	liveDotCore float32 = 8
)

// liveDot is TrayPopover LiveDot: 8px core + CSS ping (scale 1→2, fade out).
type liveDot struct {
	widget.BaseWidget
	col   color.NRGBA
	pulse bool
	ring  *canvas.Circle
	core  *canvas.Circle
	anim  *fyne.Animation
}

func newLiveDot() *liveDot {
	d := &liveDot{col: colorOK}
	d.ring = canvas.NewCircle(withAlpha(colorOK, 0x80))
	d.ring.Hide()
	d.core = canvas.NewCircle(colorOK)
	d.ExtendBaseWidget(d)
	return d
}

func (d *liveDot) Kick() {
	if d.pulse {
		d.startPulse()
	}
}

func (d *liveDot) Set(col color.NRGBA, pulse bool) {
	d.col = col
	d.core.FillColor = col
	d.core.Refresh()
	if !pulse {
		d.stopPulse()
		return
	}
	if d.pulse {
		return
	}
	d.startPulse()
}

func (d *liveDot) startPulse() {
	d.pulse = true
	d.ring.Show()
	if d.anim != nil {
		d.anim.Stop()
	}
	d.anim = fyne.NewAnimation(time.Second, func(f float32) {
		if d.ring == nil || !d.pulse {
			return
		}
		sz := liveDotCore * (1 + f)
		d.ring.FillColor = withAlpha(d.col, uint8(float32(0x80)*(1-f)))
		d.ring.Resize(fyne.NewSize(sz, sz))
		d.ring.Move(fyne.NewPos((liveDotBox-sz)/2, (liveDotBox-sz)/2))
		d.ring.Refresh()
	})
	d.anim.RepeatCount = fyne.AnimationRepeatForever
	d.anim.Curve = fyne.AnimationEaseOut
	d.anim.Start()
}

func (d *liveDot) stopPulse() {
	d.pulse = false
	if d.anim != nil {
		d.anim.Stop()
	}
	d.ring.Hide()
	d.ring.Refresh()
}

func (d *liveDot) CreateRenderer() fyne.WidgetRenderer {
	return &liveDotRender{d: d, objs: []fyne.CanvasObject{d.ring, d.core}}
}

func (d *liveDot) MinSize() fyne.Size {
	return fyne.NewSize(liveDotBox, liveDotBox)
}

type liveDotRender struct {
	d    *liveDot
	objs []fyne.CanvasObject
}

func (r *liveDotRender) Destroy() {
	if r.d != nil {
		r.d.stopPulse()
	}
}

func (r *liveDotRender) Layout(sz fyne.Size) {
	c := liveDotCore
	r.d.core.Resize(fyne.NewSize(c, c))
	r.d.core.Move(fyne.NewPos((sz.Width-c)/2, (sz.Height-c)/2))
}

func (r *liveDotRender) MinSize() fyne.Size { return fyne.NewSize(liveDotBox, liveDotBox) }

func (r *liveDotRender) Objects() []fyne.CanvasObject { return r.objs }

func (r *liveDotRender) Refresh() {
	for _, o := range r.objs {
		o.Refresh()
	}
}

type glowBG struct {
	widget.BaseWidget
	hero color.NRGBA
	srcW int
	srcH int
	img  *canvas.Image
}

func newGlowBG(hero color.NRGBA) *glowBG {
	g := &glowBG{hero: hero}
	g.img = canvas.NewImageFromImage(drawGlow(1, 1, hero))
	g.img.FillMode = canvas.ImageFillStretch
	g.img.ScaleMode = canvas.ImageScaleFastest
	g.ExtendBaseWidget(g)
	return g
}

func (g *glowBG) SetHero(c color.NRGBA) {
	if g.hero == c {
		return
	}
	g.hero = c
	g.paint()
}

func (g *glowBG) paint() {
	if g.img == nil || g.srcW < 1 || g.srcH < 1 {
		return
	}
	g.img.Image = drawGlow(g.srcW, g.srcH, g.hero)
	g.img.Refresh()
}

func (g *glowBG) MinSize() fyne.Size {
	return fyne.NewSize(1, 1)
}

func (g *glowBG) CreateRenderer() fyne.WidgetRenderer {
	return &glowRender{g: g, objs: []fyne.CanvasObject{g.img}}
}

type glowRender struct {
	g    *glowBG
	objs []fyne.CanvasObject
}

func (r *glowRender) Destroy() {}

func (r *glowRender) Layout(sz fyne.Size) {
	w := int(sz.Width)
	h := int(sz.Height)
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	if r.g.srcW != w || r.g.srcH != h {
		r.g.srcW = w
		r.g.srcH = h
		r.g.paint()
	}
	r.g.img.Move(fyne.NewPos(0, 0))
	r.g.img.Resize(sz)
}

func (r *glowRender) MinSize() fyne.Size { return fyne.NewSize(1, 1) }

func (r *glowRender) Objects() []fyne.CanvasObject { return r.objs }

func (r *glowRender) Refresh() {}

type areaSpark struct {
	widget.BaseWidget
	vals   []float64
	stroke color.NRGBA
	raster *canvas.Raster
}

func newAreaSpark(col color.NRGBA) *areaSpark {
	s := &areaSpark{stroke: col, vals: []float64{0.2, 0.2, 0.18, 0.2}}
	s.raster = canvas.NewRaster(func(w, h int) image.Image {
		return drawAreaSpark(w, h, s.vals, s.stroke)
	})
	s.ExtendBaseWidget(s)
	return s
}

func (s *areaSpark) SetValues(v []float64) {
	s.vals = append([]float64(nil), v...)
	if s.raster != nil {
		s.raster.Refresh()
	}
	s.Refresh()
}

func (s *areaSpark) CreateRenderer() fyne.WidgetRenderer {
	s.raster.SetMinSize(fyne.NewSize(120, 40))
	return widget.NewSimpleRenderer(s.raster)
}

func (s *areaSpark) MinSize() fyne.Size {
	return fyne.NewSize(40, 40)
}

type ramBar struct {
	widget.BaseWidget
	ratio  float64
	raster *canvas.Raster
}

func newRamBar() *ramBar {
	b := &ramBar{ratio: 0.12}
	b.raster = canvas.NewRaster(func(w, h int) image.Image {
		return drawRamBar(w, h, b.ratio)
	})
	b.ExtendBaseWidget(b)
	return b
}

func (b *ramBar) SetRatio(r float64) {
	b.ratio = r
	if b.raster != nil {
		b.raster.Refresh()
	}
	b.Refresh()
}

func (b *ramBar) CreateRenderer() fyne.WidgetRenderer {
	b.raster.SetMinSize(fyne.NewSize(80, 6))
	return widget.NewSimpleRenderer(b.raster)
}

func (b *ramBar) MinSize() fyne.Size {
	return fyne.NewSize(80, 6)
}

type smoothBar struct {
	widget.BaseWidget
	frac   float64
	raster *canvas.Raster
	anim   *fyne.Animation
}

func newSmoothBar() *smoothBar {
	s := &smoothBar{}
	s.raster = canvas.NewRaster(func(w, h int) image.Image {
		return drawProgressBar(w, h, s.frac)
	})
	s.ExtendBaseWidget(s)
	return s
}

func (s *smoothBar) SetValue(v float64) {
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	from := s.frac
	if s.anim != nil {
		s.anim.Stop()
	}
	s.anim = fyne.NewAnimation(400*time.Millisecond, func(f float32) {
		s.frac = from + (v-from)*float64(f)
		if s.raster != nil {
			s.raster.Refresh()
		}
	})
	s.anim.Curve = fyne.AnimationEaseOut
	s.anim.Start()
}

func (s *smoothBar) MinSize() fyne.Size {
	return fyne.NewSize(80, 4)
}

func (s *smoothBar) CreateRenderer() fyne.WidgetRenderer {
	s.raster.SetMinSize(fyne.NewSize(80, 4))
	return widget.NewSimpleRenderer(s.raster)
}

func lucide14(kind string, col color.NRGBA) fyne.CanvasObject {
	img := canvas.NewImageFromResource(drawMiniIcon(kind, col))
	img.FillMode = canvas.ImageFillContain
	img.SetMinSize(fyne.NewSize(14, 14))
	slot := canvas.NewRectangle(color.Transparent)
	slot.SetMinSize(fyne.NewSize(14, 14))
	return container.NewCenter(container.NewStack(slot, img))
}

func metricWell(kind string, col color.NRGBA) fyne.CanvasObject {
	well := canvas.NewRectangle(withAlpha(col, 0x22))
	well.CornerRadius = 14
	well.SetMinSize(fyne.NewSize(dashIconWell, dashIconWell))
	slot := canvas.NewRectangle(color.Transparent)
	slot.SetMinSize(fyne.NewSize(dashIconWell, dashIconWell))
	return container.NewCenter(container.NewStack(slot, well, lucide14(kind, col)))
}

type dragFrame struct {
	widget.BaseWidget
	content    fyne.CanvasObject
	host       func() fyne.Window
	nativeDrag bool
}

func newDragFrame(content fyne.CanvasObject, host func() fyne.Window) *dragFrame {
	d := &dragFrame{content: content, host: host}
	d.ExtendBaseWidget(d)
	return d
}

func (d *dragFrame) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(d.content)
}

func (d *dragFrame) MouseDown(ev *desktop.MouseEvent) {
	if ev.Button != desktop.MouseButtonPrimary || d.host == nil {
		return
	}
	w := d.host()
	if w == nil {
		return
	}
	if startNativeWindowDrag(w) {
		d.nativeDrag = true
	}
}

func (d *dragFrame) MouseUp(*desktop.MouseEvent) {}

func (d *dragFrame) Dragged(ev *fyne.DragEvent) {
	if d.nativeDrag {
		return
	}
	if d.host == nil {
		return
	}
	if ev.Dragged.DX == 0 && ev.Dragged.DY == 0 {
		return
	}
	w := d.host()
	if w == nil {
		return
	}
	if startNativeWindowDrag(w) {
		d.nativeDrag = true
		return
	}
	moveNativeWindow(w, ev.Dragged.DX, ev.Dragged.DY)
}

func (d *dragFrame) DragEnd() {
	d.nativeDrag = false
}

var (
	_ fyne.Draggable    = (*dragFrame)(nil)
	_ desktop.Mouseable = (*dragFrame)(nil)
)

func labelCaps(s string, size float32, col color.Color) *canvas.Text {
	t := canvas.NewText(s, col)
	t.TextSize = size
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

func numText(s string, size float32, col color.Color) *canvas.Text {
	t := canvas.NewText(s, col)
	t.TextSize = size
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

func gapH(h float32) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(1, h))
	return r
}

type stripLayout struct{ height float32 }

func (s stripLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	w := float32(1)
	for _, o := range objects {
		if m := o.MinSize(); m.Width > w {
			w = m.Width
		}
	}
	return fyne.NewSize(w, s.height)
}

func (s stripLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objects {
		o.Resize(fyne.NewSize(size.Width, s.height))
		o.Move(fyne.NewPos(0, 0))
	}
}

func lockH(h float32, obj fyne.CanvasObject) fyne.CanvasObject {
	return container.New(stripLayout{height: h}, obj)
}

type meterLay struct{}

func (meterLay) MinSize(objects []fyne.CanvasObject) fyne.Size {
	cw := float32(28)
	ch := float32(14)
	if len(objects) > 1 && objects[1] != nil {
		m := objects[1].MinSize()
		cw, ch = m.Width, m.Height
	}
	h := float32(4)
	if ch > h {
		h = ch
	}
	return fyne.NewSize(80+12+cw, h)
}

func (meterLay) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) < 2 {
		return
	}
	bar, count := objects[0], objects[1]
	cm := count.MinSize()
	count.Move(fyne.NewPos(size.Width-cm.Width, (size.Height-cm.Height)/2))
	count.Resize(cm)
	const bh float32 = 4
	bar.Move(fyne.NewPos(0, (size.Height-bh)/2))
	bw := size.Width - cm.Width - 12
	if bw < 8 {
		bw = 8
	}
	bar.Resize(fyne.NewSize(bw, bh))
}

type heroFace struct {
	widget.BaseWidget
	tone   color.NRGBA
	kind   heroKind
	raster *canvas.Raster
}

func newHeroFace() *heroFace {
	h := &heroFace{tone: colorOK, kind: heroOK}
	h.raster = canvas.NewRaster(func(w, ht int) image.Image {
		n := w
		if ht > n {
			n = ht
		}
		if n < 64 {
			n = 64
		}
		return drawHero(n, h.tone, h.kind)
	})
	h.ExtendBaseWidget(h)
	return h
}

func (h *heroFace) Set(tone color.NRGBA, kind heroKind) {
	if h.tone == tone && h.kind == kind {
		return
	}
	h.tone = tone
	h.kind = kind
	if h.raster != nil {
		h.raster.Refresh()
	}
}

func (h *heroFace) CreateRenderer() fyne.WidgetRenderer {
	h.raster.SetMinSize(fyne.NewSize(64, 64))
	return widget.NewSimpleRenderer(h.raster)
}

func (h *heroFace) MinSize() fyne.Size {
	return fyne.NewSize(64, 64)
}

type iconDot struct {
	widget.BaseWidget
	kind   string
	col    color.NRGBA
	raster *canvas.Raster
}

func newIconDot(kind string, col color.NRGBA) *iconDot {
	d := &iconDot{kind: kind, col: col}
	d.raster = canvas.NewRaster(func(w, ht int) image.Image {
		return paintMiniIconAt(d.kind, d.col, w, ht)
	})
	d.ExtendBaseWidget(d)
	return d
}

func (d *iconDot) Set(kind string, col color.NRGBA) {
	if d.kind == kind && d.col == col {
		return
	}
	d.kind = kind
	d.col = col
	if d.raster != nil {
		d.raster.Refresh()
	}
}

func (d *iconDot) CreateRenderer() fyne.WidgetRenderer {
	d.raster.SetMinSize(fyne.NewSize(12, 12))
	return widget.NewSimpleRenderer(d.raster)
}

func (d *iconDot) MinSize() fyne.Size {
	return fyne.NewSize(12, 12)
}
