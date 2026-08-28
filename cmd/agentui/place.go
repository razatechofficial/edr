package main

import (
	"sync"
	"time"

	"fyne.io/fyne/v2"
)

var (
	becomeActiveMu sync.Mutex
	becomeActiveFn func()
	uiStartedAt    = time.Now()
	lastTrayTap    = time.Time{}
)

func setBecomeActive(fn func()) {
	becomeActiveMu.Lock()
	becomeActiveFn = fn
	becomeActiveMu.Unlock()
}

func invokeBecomeActive() {
	if time.Since(uiStartedAt) < 2*time.Second {
		return
	}
	becomeActiveMu.Lock()
	fn := becomeActiveFn
	becomeActiveMu.Unlock()
	if fn != nil {
		fyne.Do(fn)
	}
}

func bringWindowForward(w fyne.Window) {
	if w == nil {
		return
	}
	w.Show()
	w.RequestFocus()
	bringNativeWindow(w)
}
