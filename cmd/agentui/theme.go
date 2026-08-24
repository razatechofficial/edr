package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

var (
	colorBg     = color.NRGBA{R: 0x07, G: 0x11, B: 0x1A, A: 0xFF}
	colorCard   = color.NRGBA{R: 0x0E, G: 0x1A, B: 0x26, A: 0xFF}
	colorInput  = color.NRGBA{R: 0x12, G: 0x22, B: 0x30, A: 0xFF}
	colorCyan   = color.NRGBA{R: 0x2E, G: 0xE6, B: 0xD6, A: 0xFF}
	colorText   = color.NRGBA{R: 0xE8, G: 0xF1, B: 0xF8, A: 0xFF}
	colorMuted  = color.NRGBA{R: 0x8B, G: 0xA0, B: 0xB3, A: 0xFF}
	colorOK     = color.NRGBA{R: 0x3D, G: 0xDC, B: 0x82, A: 0xFF}
	colorWarn   = color.NRGBA{R: 0xF5, G: 0xA5, B: 0x24, A: 0xFF}
	colorDanger = color.NRGBA{R: 0xFF, G: 0x6B, B: 0x4A, A: 0xFF}
	colorOnCyan = color.NRGBA{R: 0x07, G: 0x11, B: 0x1A, A: 0xFF}
	colorHover  = color.NRGBA{R: 0x16, G: 0x2C, B: 0x3C, A: 0xFF}
	colorSep    = color.NRGBA{R: 0x1C, G: 0x32, B: 0x44, A: 0xFF}
	colorPink   = color.NRGBA{R: 0xFF, G: 0x6B, B: 0x9A, A: 0xFF}
)

type edrTheme struct{}

func (edrTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground, theme.ColorNameOverlayBackground, theme.ColorNameMenuBackground:
		return colorBg
	case theme.ColorNameForeground:
		return colorText
	case theme.ColorNameDisabled:
		return colorMuted
	case theme.ColorNamePlaceHolder:
		return colorMuted
	case theme.ColorNameButton, theme.ColorNameInputBackground, theme.ColorNameHeaderBackground:
		return colorInput
	case theme.ColorNameDisabledButton:
		return colorCard
	case theme.ColorNamePrimary, theme.ColorNameHyperlink:
		return colorCyan
	case theme.ColorNameForegroundOnPrimary:
		return colorOnCyan
	case theme.ColorNameSuccess:
		return colorOK
	case theme.ColorNameError:
		return colorDanger
	case theme.ColorNameWarning:
		return colorWarn
	case theme.ColorNameFocus:
		return colorCyan
	case theme.ColorNameHover, theme.ColorNamePressed:
		return colorHover
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x2E, G: 0xE6, B: 0xD6, A: 0x40}
	case theme.ColorNameSeparator, theme.ColorNameShadow:
		return colorSep
	case theme.ColorNameInputBorder:
		return colorSep
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (edrTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (edrTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (edrTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 10
	case theme.SizeNameInnerPadding:
		return 8
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return 8
	}
	return theme.DefaultTheme().Size(name)
}
