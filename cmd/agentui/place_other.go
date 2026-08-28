//go:build !darwin && !windows

package main

import "fyne.io/fyne/v2"

func registerAppActivate() {}

func placeNearTray(fyne.Window, float32, float32, bool, bool) {}

func moveNativeWindow(fyne.Window, float32, float32) {}

func bringNativeWindow(fyne.Window) {}
