//go:build !darwin && !windows

package main

import "fyne.io/fyne/v2"

func registerAppActivate() {}

func placeNearTray(fyne.Window, float32, float32, bool, bool) {}

func moveNativeWindow(fyne.Window, float32, float32) {}

func nativeResizeKeepTop(fyne.Window, float32, float32) bool { return false }

func startNativeWindowDrag(fyne.Window) bool { return false }

func bringNativeWindow(fyne.Window) {}
