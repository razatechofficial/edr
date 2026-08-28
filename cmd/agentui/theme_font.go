package main

import (
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

var (
	fontOnce sync.Once
	fontReg  fyne.Resource
	fontBold fyne.Resource
	fontMono fyne.Resource
)

func nativeFont(style fyne.TextStyle) fyne.Resource {
	fontOnce.Do(loadNativeFonts)
	if style.Monospace && fontMono != nil {
		return fontMono
	}
	if style.Bold && fontBold != nil {
		return fontBold
	}
	if fontReg != nil {
		return fontReg
	}
	return theme.DefaultTheme().Font(style)
}

func loadNativeFonts() {
	fontReg = firstFont(
		"/System/Library/Fonts/SFNS.ttf",
		"/System/Library/Fonts/SFCompact.ttf",
		`C:\Windows\Fonts\segoeui.ttf`,
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
	)
	fontBold = firstFont(
		"/System/Library/Fonts/SFNS.ttf",
		"/System/Library/Fonts/Supplemental/Arial Bold.ttf",
		`C:\Windows\Fonts\seguisb.ttf`,
		"/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
	)
	fontMono = firstFont(
		"/System/Library/Fonts/SFNSMono.ttf",
		`C:\Windows\Fonts\consola.ttf`,
		"/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
	)
	if fontBold == nil {
		fontBold = fontReg
	}
}

func firstFont(paths ...string) fyne.Resource {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil || len(b) < 64 {
			continue
		}
		return fyne.NewStaticResource(p, b)
	}
	return nil
}
