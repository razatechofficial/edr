package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Native host chrome — system dark, not the XDR console (no mint, no pink).
var (
	colorBg       = color.NRGBA{R: 0x1C, G: 0x1C, B: 0x1E, A: 0xFF}
	colorCard     = color.NRGBA{R: 0x2C, G: 0x2C, B: 0x2E, A: 0xFF}
	colorInput    = color.NRGBA{R: 0x3A, G: 0x3A, B: 0x3C, A: 0xFF}
	colorAccent   = color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0xFF}
	colorText     = color.NRGBA{R: 0xF5, G: 0xF5, B: 0xF7, A: 0xFF}
	colorMuted    = color.NRGBA{R: 0x8E, G: 0x8E, B: 0x93, A: 0xFF}
	colorOK       = color.NRGBA{R: 0x32, G: 0xD7, B: 0x4B, A: 0xFF}
	colorWarn     = color.NRGBA{R: 0xFF, G: 0xD6, B: 0x0A, A: 0xFF}
	colorDanger   = color.NRGBA{R: 0xFF, G: 0x45, B: 0x3A, A: 0xFF}
	colorOnAccent = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	colorHover    = color.NRGBA{R: 0x3A, G: 0x3A, B: 0x3C, A: 0xFF}
	colorSep      = color.NRGBA{R: 0x48, G: 0x48, B: 0x4A, A: 0xFF}
	colorCyan     = color.NRGBA{R: 0x5A, G: 0xC8, B: 0xFF, A: 0xFF}
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
		return colorAccent
	case theme.ColorNameForegroundOnPrimary:
		return colorOnAccent
	case theme.ColorNameSuccess:
		return colorOK
	case theme.ColorNameError:
		return colorDanger
	case theme.ColorNameWarning:
		return colorWarn
	case theme.ColorNameFocus:
		return colorAccent
	case theme.ColorNameHover, theme.ColorNamePressed:
		return colorHover
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x0A, G: 0x84, B: 0xFF, A: 0x40}
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
