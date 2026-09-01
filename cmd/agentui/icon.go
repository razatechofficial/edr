package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

func edrIcon() fyne.Resource {
	const n = 64
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	fill := color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0xFF}
	core := color.NRGBA{R: 0x1C, G: 0x1C, B: 0x1E, A: 0xFF}
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

// edrTrayIcon is a 22pt-class template (44px @2x): opaque black on transparent.
// Fyne promotes ThemedResource to NSImage.template so the menu bar inverts it.
func edrTrayIcon() fyne.Resource {
	const n = 44
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	ink := color.NRGBA{A: 0xFF}
	cx, cy := n/2, n/2
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := x-cx, y-cy
			d2 := dx*dx + dy*dy
			if d2 <= 18*18 && d2 >= 8*8 {
				img.SetNRGBA(x, y, ink)
			}
			if d2 <= 4*4 {
				img.SetNRGBA(x, y, ink)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return fyne.NewStaticResource("edr-tray.png", buf.Bytes())
}

func edrTrayResource() fyne.Resource {
	return theme.NewThemedResource(edrTrayIcon())
}
