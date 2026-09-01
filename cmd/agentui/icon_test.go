package main

import (
	"bytes"
	"image/png"
	"testing"

	"fyne.io/fyne/v2/theme"
)

func TestEdrTrayIconIsTemplateSized(t *testing.T) {
	res := edrTrayIcon()
	img, err := png.Decode(bytes.NewReader(res.Content()))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	if b.Dx() != 44 || b.Dy() != 44 {
		t.Fatalf("tray icon %dx%d, want 44x44", b.Dx(), b.Dy())
	}
	var opaque, clear int
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := img.At(x, y).RGBA()
			if a > 0 {
				opaque++
			} else {
				clear++
			}
		}
	}
	if opaque == 0 || clear == 0 {
		t.Fatalf("template icon needs both ink and transparency (opaque=%d clear=%d)", opaque, clear)
	}
}

func TestEdrTrayResourceIsThemed(t *testing.T) {
	if _, ok := edrTrayResource().(*theme.ThemedResource); !ok {
		t.Fatalf("got %T, want *theme.ThemedResource (Fyne uses SetTemplateIcon only for that type)", edrTrayResource())
	}
}
