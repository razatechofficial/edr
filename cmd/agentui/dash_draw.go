package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"

	"fyne.io/fyne/v2"
)

type heroKind int

const (
	heroOK heroKind = iota
	heroAlert
	heroOff
)

func withAlpha(c color.NRGBA, a uint8) color.NRGBA {
	c.A = a
	return c
}

func mixNRGBA(a, b color.NRGBA, t float64) color.NRGBA {
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	it := 1 - t
	return color.NRGBA{
		R: uint8(float64(a.R)*it + float64(b.R)*t),
		G: uint8(float64(a.G)*it + float64(b.G)*t),
		B: uint8(float64(a.B)*it + float64(b.B)*t),
		A: uint8(float64(a.A)*it + float64(b.A)*t),
	}
}

func drawHeroWell(w, h int, tone color.NRGBA) *image.NRGBA {
	if w < 8 {
		w = 8
	}
	if h < 8 {
		h = 8
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	rad := 16.0
	if float64(w) < rad*2 {
		rad = float64(w) / 2
	}
	start := withAlpha(tone, 0x70)
	end := colorBg
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !roundRect(float64(x), float64(y), float64(w), float64(h), rad) {
				continue
			}
			t := (float64(x)*0.35 + float64(y)*0.94) / math.Max(1, math.Hypot(float64(w), float64(h)))
			if t > 1 {
				t = 1
			}
			c := mixNRGBA(start, end, t)
			c.A = 255
			img.SetNRGBA(x, y, c)
		}
	}
	hi := color.NRGBA{R: 255, G: 255, B: 255, A: 0x24}
	for x := int(rad / 2); x < w-int(rad/2); x++ {
		img.SetNRGBA(x, 1, hi)
	}
	return img
}

func roundRect(x, y, w, h, r float64) bool {
	if x >= r && x < w-r {
		return y >= 0 && y < h
	}
	if y >= r && y < h-r {
		return x >= 0 && x < w
	}
	cx, cy := r, r
	if x >= w-r {
		cx = w - r
	}
	if y >= h-r {
		cy = h - r
	}
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}

func drawGlow(w, h int, hero color.NRGBA) *image.NRGBA {
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	bg := colorBg
	fw, fh := float64(w), float64(h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			px, py := float64(x), float64(y)
			a1 := radial(px, py, fw*0.5, 0, fw*0.52, fh*0.40)
			a2 := radial(px, py, 0, 0, fw*0.80, fh*0.62)
			a := a1*0.72 + a2*0.55
			if a > 1 {
				a = 1
			}
			c := mixNRGBA(bg, withAlpha(hero, 255), a*0.38)
			c.A = 255
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

func radial(px, py, cx, cy, rx, ry float64) float64 {
	if rx < 1 {
		rx = 1
	}
	if ry < 1 {
		ry = 1
	}
	dx := (px - cx) / rx
	dy := (py - cy) / ry
	d := math.Hypot(dx, dy)
	if d >= 1 {
		return 0
	}
	t := 1 - d
	return t * t
}

func drawHero(size int, tone color.NRGBA, kind heroKind) *image.NRGBA {
	if size < 16 {
		size = 16
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	fs := float64(size)
	r := fs * 0.31
	ink := colorBg
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			d := roundBox(float64(x)+0.5, float64(y)+0.5, fs/2, fs/2, fs/2-0.5, fs/2-0.5, r)
			if d > 1 {
				continue
			}
			t := float64(x+y) / (2 * fs)
			fill := mixNRGBA(withAlpha(tone, 0x55), ink, 0.35+t*0.45)
			if d > 0 {
				fill = mixNRGBA(fill, color.NRGBA{R: 255, G: 255, B: 255, A: 40}, 0.12)
			}
			edge := 1 - math.Min(1, math.Abs(d)/1.4)
			if edge > 0 {
				fill = mixNRGBA(fill, color.NRGBA{R: 255, G: 255, B: 255, A: 255}, edge*0.10)
			}
			fill.A = 255
			img.SetNRGBA(x, y, fill)
		}
	}
	shieldBox := fs * 0.50
	ox := (fs - shieldBox) / 2
	sw := shieldBox * (1.6 / 24)
	shield := lucidePtsIn(shieldBox, ox, ox, [][2]float64{
		{12, 22}, {20, 18}, {20, 9}, {12, 6}, {4, 9}, {4, 18},
	})
	strokePoly(img, shield, tone, sw)
	switch kind {
	case heroAlert:
		strokeLine(img, fs*0.50, ox+shieldBox*8/24, fs*0.50, ox+shieldBox*12/24, tone, sw)
		fillCircle(img, fs*0.50, ox+shieldBox*16/24, sw*0.7, tone)
	case heroOff:
		strokeLine(img, ox+shieldBox*0.22, ox+shieldBox*0.22, ox+shieldBox*0.78, ox+shieldBox*0.78, tone, sw)
	}
	return img
}

func lucidePts(size float64, pts [][2]float64) [][2]float64 {
	return lucidePtsIn(size, 0, 0, pts)
}

func lucidePtsIn(size, ox, oy float64, pts [][2]float64) [][2]float64 {
	out := make([][2]float64, len(pts))
	s := size / 24
	for i, p := range pts {
		out[i] = [2]float64{ox + p[0]*s, oy + p[1]*s}
	}
	return out
}

func strokeArc(img *image.NRGBA, cx, cy, r, a0, a1 float64, col color.NRGBA, width float64) {
	n := int(math.Abs(a1-a0)*r) + 8
	if n < 6 {
		n = 6
	}
	for i := 0; i < n; i++ {
		t0 := a0 + (a1-a0)*float64(i)/float64(n)
		t1 := a0 + (a1-a0)*float64(i+1)/float64(n)
		strokeLine(img, cx+math.Cos(t0)*r, cy+math.Sin(t0)*r, cx+math.Cos(t1)*r, cy+math.Sin(t1)*r, col, width)
	}
}

func roundBox(px, py, cx, cy, hx, hy, r float64) float64 {
	dx := math.Abs(px-cx) - (hx - r)
	dy := math.Abs(py-cy) - (hy - r)
	ox, oy := math.Max(dx, 0), math.Max(dy, 0)
	return math.Hypot(ox, oy) + math.Min(math.Max(dx, dy), 0) - r
}

func strokePoly(img *image.NRGBA, pts [][2]float64, col color.NRGBA, width float64) {
	if len(pts) < 2 {
		return
	}
	for i := 0; i < len(pts); i++ {
		a := pts[i]
		b := pts[(i+1)%len(pts)]
		strokeLine(img, a[0], a[1], b[0], b[1], col, width)
	}
}

func strokeLine(img *image.NRGBA, x0, y0, x1, y1 float64, col color.NRGBA, width float64) {
	dx, dy := x1-x0, y1-y0
	n := int(math.Hypot(dx, dy)*2 + 2)
	if n < 2 {
		n = 2
	}
	r := width / 2
	for i := 0; i <= n; i++ {
		t := float64(i) / float64(n)
		fillCircle(img, x0+dx*t, y0+dy*t, r, col)
	}
}

func fillCircle(img *image.NRGBA, cx, cy, r float64, col color.NRGBA) {
	b := img.Bounds()
	r2 := r * r
	minX := int(math.Floor(cx - r - 1))
	maxX := int(math.Ceil(cx + r + 1))
	minY := int(math.Floor(cy - r - 1))
	maxY := int(math.Ceil(cy + r + 1))
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if !image.Pt(x, y).In(b) {
				continue
			}
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			if dx*dx+dy*dy <= r2 {
				img.SetNRGBA(x, y, col)
			}
		}
	}
}

func drawAreaSpark(w, h int, vals []float64, col color.NRGBA) *image.NRGBA {
	if w < 2 {
		w = 2
	}
	if h < 2 {
		h = 2
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	if len(vals) == 0 {
		vals = []float64{0.2, 0.2}
	} else if len(vals) == 1 {
		vals = []float64{vals[0], vals[0]}
	}
	max := 0.5
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	n := len(vals)
	step := float64(w-1) / float64(n-1)
	if step <= 0 || math.IsInf(step, 0) || math.IsNaN(step) {
		step = float64(w - 1)
	}
	ys := make([]float64, n)
	for i, v := range vals {
		ys[i] = float64(h-2) - (v/max)*float64(h-4)
	}
	for x := 0; x < w; x++ {
		t := float64(x) / step
		i := int(t)
		if i < 0 {
			i = 0
		}
		if i >= n-1 {
			i = n - 2
		}
		f := t - float64(i)
		y := ys[i]*(1-f) + ys[i+1]*f
		yi := int(y)
		if yi < 0 {
			yi = 0
		}
		for py := yi; py < h; py++ {
			fade := 1 - float64(py-yi)/float64(h)
			if fade < 0 {
				fade = 0
			}
			a := uint8(fade * 0.45 * 255)
			img.SetNRGBA(x, py, withAlpha(col, a))
		}
	}
	for i := 0; i < n-1; i++ {
		strokeLine(img, float64(i)*step, ys[i], float64(i+1)*step, ys[i+1], col, 2)
	}
	fillCircle(img, float64(w-1), ys[n-1], 2.6, col)
	return img
}

func drawProgressBar(w, h int, ratio float64) *image.NRGBA {
	if w < 2 {
		w = 2
	}
	if h < 2 {
		h = 2
	}
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	track := color.NRGBA{R: 255, G: 255, B: 255, A: 22}
	fillW := int(math.Round(float64(w) * ratio))
	r := float64(h) / 2
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if !inPill(float64(x), float64(y), float64(w), float64(h), r) {
				continue
			}
			if x >= fillW {
				img.SetNRGBA(x, y, track)
				continue
			}
			t := float64(x) / math.Max(1, float64(w-1))
			var c color.NRGBA
			if t < 0.5 {
				c = mixNRGBA(colorCyan, colorAccent, t*2)
			} else {
				c = mixNRGBA(colorAccent, colorPurple, (t-0.5)*2)
			}
			c.A = 255
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

func inPill(x, y, w, h, r float64) bool {
	if x >= r && x < w-r {
		return true
	}
	cx := r
	if x >= w-r {
		cx = w - r
	}
	dx, dy := x-cx, y-r
	return dx*dx+dy*dy <= r*r
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func pillCoverage(px, py, w, h float64) float64 {
	if w < 0.5 || h < 0.5 {
		return 0
	}
	r := math.Min(h, w) / 2
	dx := math.Abs(px-w/2) - (w/2 - r)
	dy := math.Abs(py-h/2) - (h/2 - r)
	if dx < 0 {
		dx = 0
	}
	if dy < 0 {
		dy = 0
	}
	return clamp01(0.5 - (math.Hypot(dx, dy) - r))
}

func withCover(c color.NRGBA, cover float64) color.NRGBA {
	if cover <= 0 {
		return color.NRGBA{}
	}
	if cover < 1 {
		c.A = uint8(math.Round(float64(c.A) * cover))
	}
	return c
}

func srcOver(dst, src color.NRGBA) color.NRGBA {
	sa := float64(src.A) / 255
	if sa <= 0 {
		return dst
	}
	if sa >= 1 {
		return src
	}
	da := float64(dst.A) / 255
	outA := sa + da*(1-sa)
	if outA <= 0 {
		return color.NRGBA{}
	}
	inv := 1 - sa
	return color.NRGBA{
		R: uint8(math.Round((float64(src.R)*sa + float64(dst.R)*da*inv) / outA)),
		G: uint8(math.Round((float64(src.G)*sa + float64(dst.G)*da*inv) / outA)),
		B: uint8(math.Round((float64(src.B)*sa + float64(dst.B)*da*inv) / outA)),
		A: uint8(math.Round(outA * 255)),
	}
}

func drawShareBar(w, h int, edr, other, free float64) *image.NRGBA {
	if w < 2 {
		w = 2
	}
	if h < 2 {
		h = 2
	}
	if edr < 0 {
		edr = 0
	}
	if other < 0 {
		other = 0
	}
	if free < 0 {
		free = 0
	}
	sum := edr + other + free
	if sum <= 0 {
		free = 1
		sum = 1
	}
	edr, other, free = edr/sum, other/sum, free/sum

	fw, fh := float64(w), float64(h)
	minCap := fh
	edrPx := fw * edr
	usedPx := fw * (edr + other)
	if edr > 0 && edrPx < minCap {
		edrPx = minCap
	}
	if edr+other > 0 && usedPx < minCap {
		usedPx = minCap
	}
	if usedPx < edrPx {
		usedPx = edrPx
	}
	if usedPx > fw {
		usedPx = fw
	}
	if edrPx > usedPx {
		edrPx = usedPx
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	track := color.NRGBA{R: 255, G: 255, B: 255, A: 20} // web: rgba(255,255,255,0.08)
	edrFill := colorCyan
	otherFill := colorPurple
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5
			c := withCover(track, pillCoverage(px, py, fw, fh))
			if usedPx > 0.5 {
				c = srcOver(c, withCover(otherFill, pillCoverage(px, py, usedPx, fh)))
			}
			if edrPx > 0.5 {
				c = srcOver(c, withCover(edrFill, pillCoverage(px, py, edrPx, fh)))
			}
			img.SetNRGBA(x, y, c)
		}
	}
	return img
}

func pngResource(name string, img image.Image) fyne.Resource {
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return fyne.NewStaticResource(name, buf.Bytes())
}

func heroResource(tone color.NRGBA, kind heroKind) fyne.Resource {
	return pngResource("hero.png", drawHero(128, tone, kind))
}

func drawMiniIcon(kind string, col color.NRGBA) fyne.Resource {
	return pngResource(kind+".png", paintMiniIconAt(kind, col, 64, 64))
}

func paintMiniIcon(kind string, col color.NRGBA) *image.NRGBA {
	return paintMiniIconAt(kind, col, 32, 32)
}

func paintMiniIconAt(kind string, col color.NRGBA, w, h int) *image.NRGBA {
	n := w
	if h > n {
		n = h
	}
	if n < 16 {
		n = 16
	}
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	s := float64(n)
	sw := s * (2.0 / 24.0)
	if sw < 1.4 {
		sw = 1.4
	}
	switch kind {
	case "activity":
		// Lucide Activity polyline (24 viewBox).
		pts := lucidePts(s, [][2]float64{{22, 12}, {18, 12}, {15, 21}, {9, 3}, {6, 12}, {2, 12}})
		for i := 0; i < len(pts)-1; i++ {
			strokeLine(img, pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1], col, sw)
		}
	case "alert":
		strokePoly(img, lucidePts(s, [][2]float64{{12, 22}, {20, 18}, {20, 9}, {12, 6}, {4, 9}, {4, 18}}), col, sw)
		strokeLine(img, s*12/24, s*8/24, s*12/24, s*12/24, col, sw)
		fillCircle(img, s*12/24, s*16/24, sw*0.65, col)
	case "ban":
		cx, cy, r := s*0.50, s*0.50, s*(10.0/24.0)
		strokeArc(img, cx, cy, r, 0, 2*math.Pi, col, sw)
		strokeLine(img, s*4.93/24, s*4.93/24, s*19.07/24, s*19.07/24, col, sw)
	case "wifi":
		paintWifi(img, s, sw, col, false)
	case "wifi-off":
		paintWifi(img, s, sw, col, true)
	case "chevron-right":
		pts := lucidePts(s, [][2]float64{{9, 18}, {15, 12}, {9, 6}})
		strokeLine(img, pts[0][0], pts[0][1], pts[1][0], pts[1][1], col, sw)
		strokeLine(img, pts[1][0], pts[1][1], pts[2][0], pts[2][1], col, sw)
	case "chevron-down":
		pts := lucidePts(s, [][2]float64{{6, 9}, {12, 15}, {18, 9}})
		strokeLine(img, pts[0][0], pts[0][1], pts[1][0], pts[1][1], col, sw)
		strokeLine(img, pts[1][0], pts[1][1], pts[2][0], pts[2][1], col, sw)
	case "check":
		pts := lucidePts(s, [][2]float64{{20, 6}, {9, 17}, {4, 12}})
		strokeLine(img, pts[0][0], pts[0][1], pts[1][0], pts[1][1], col, sw*1.2)
		strokeLine(img, pts[1][0], pts[1][1], pts[2][0], pts[2][1], col, sw*1.2)
	case "spinner":
		paintSpinnerAt(img, s, sw, col, 0)
	case "lock":
		strokeArc(img, s*12/24, s*10/24, s*4.2/24, math.Pi, 2*math.Pi, col, sw)
		x0, y0, x1, y1 := s*7/24, s*11/24, s*17/24, s*21/24
		strokeLine(img, x0, y0, x1, y0, col, sw)
		strokeLine(img, x1, y0, x1, y1, col, sw)
		strokeLine(img, x1, y1, x0, y1, col, sw)
		strokeLine(img, x0, y1, x0, y0, col, sw)
	case "fingerprint":
		strokeArc(img, s*12/24, s*13/24, s*3.2/24, 0.4, math.Pi*1.6, col, sw)
		strokeArc(img, s*12/24, s*13/24, s*5.6/24, 0.25, math.Pi*1.75, col, sw)
		strokeArc(img, s*12/24, s*13/24, s*8.0/24, 0.15, math.Pi*1.85, col, sw)
	case "shield":
		strokePoly(img, lucidePts(s, [][2]float64{{12, 22}, {20, 18}, {20, 8}, {12, 4}, {4, 8}, {4, 18}}), col, sw)
	}
	return img
}

func paintSpinnerAt(img *image.NRGBA, s, sw float64, col color.NRGBA, phase int) {
	cx, cy := s*0.5, s*0.5
	phase %= 8
	if phase < 0 {
		phase += 8
	}
	for i := 0; i < 8; i++ {
		spoke := (i + phase) % 8
		a := float64(spoke)*math.Pi*2/8 - math.Pi/2
		op := 0.22 + float64(i)/7*0.78
		c := withAlpha(col, uint8(op*255))
		strokeLine(img, cx+math.Cos(a)*s*0.21, cy+math.Sin(a)*s*0.21, cx+math.Cos(a)*s*0.40, cy+math.Sin(a)*s*0.40, c, sw)
	}
}

func drawSpinnerPhase(phase int) fyne.Resource {
	phase %= 8
	if phase < 0 {
		phase += 8
	}
	col := color.NRGBA{R: 0x64, G: 0xD2, B: 0xFF, A: 0xFF}
	name := "spin-" + string(rune('0'+phase)) + ".png"
	return pngResource(name, paintSpinnerPhase(col, phase))
}

func paintSpinnerPhase(col color.NRGBA, phase int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, 64, 64))
	s := 64.0
	sw := s * (2.0 / 24.0)
	if sw < 1.4 {
		sw = 1.4
	}
	paintSpinnerAt(img, s, sw, col, phase)
	return img
}

func paintWifi(img *image.NRGBA, s, sw float64, col color.NRGBA, off bool) {
	cx, cy := s*12/24, s*20/24
	a0, a1 := math.Pi*1.20, math.Pi*1.80
	strokeArc(img, cx, cy, s*12/24, a0, a1, col, sw)
	strokeArc(img, cx, cy, s*8/24, a0, a1, col, sw)
	strokeArc(img, cx, cy, s*4.2/24, a0, a1, col, sw)
	fillCircle(img, cx, cy, sw*0.7, col)
	if off {
		strokeLine(img, s*5/24, s*19/24, s*19/24, s*5/24, col, sw)
	}
}
