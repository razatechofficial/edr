package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"

	"fyne.io/fyne/v2"
)

func edrIcon() fyne.Resource {
	const n = 64
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	fill := color.NRGBA{R: 0x2E, G: 0xE6, B: 0xD6, A: 0xFF}
	core := color.NRGBA{R: 0x07, G: 0x11, B: 0x1A, A: 0xFF}
	cx, cy := n/2, n/2
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := x-cx, y-cy
			d2 := dx*dx + dy*dy
			if d2 <= 26*26 {
				img.SetNRGBA(x, y, fill)
			}
			if d2 <= 16*16 {
				img.SetNRGBA(x, y, core)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return fyne.NewStaticResource("edr-agent.png", buf.Bytes())
}
