package main

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func runDashboard() error {
	a := app.NewWithID("com.razatech.edr.console")
	w := a.NewWindow("EDR Agent")
	w.Resize(fyne.NewSize(760, 660))
	w.SetMaster()

	stateVal := widget.NewLabelWithStyle("…", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	stateDetail := widget.NewLabel("…")
	diagVal := widget.NewLabel("…")

	serviceVal := widget.NewLabel("…")
	enrollVal := widget.NewLabel("…")
	agentVal := widget.NewLabel("…")
	ingestVal := widget.NewLabel("…")
	runtimeVal := widget.NewLabel("…")
	detectVal := widget.NewLabel("…")
	updatedVal := widget.NewLabel("…")
	for _, l := range []*widget.Label{stateDetail, diagVal, serviceVal, enrollVal, agentVal, ingestVal, runtimeVal, detectVal, updatedVal} {
		l.Wrapping = fyne.TextWrapWord
	}

	token := widget.NewPasswordEntry()
	token.SetPlaceHolder("Enrollment token from the XDR console")
	activity := widget.NewMultiLineEntry()
	activity.Disable()
	activity.SetMinRowsVisible(8)

	appendActivity := func(title, body string, err error) {
		stamp := time.Now().Format("15:04:05")
		msg := body
		if err != nil && msg == "" {
			msg = err.Error()
		}
		if msg == "" {
			msg = "ok"
		}
		prev := activity.Text
		line := fmt.Sprintf("[%s] %s\n%s\n", stamp, title, msg)
		if prev != "" {
			line = line + "\n" + prev
		}
		if len(line) > 8000 {
			line = line[:8000] + "\n…"
		}
		activity.SetText(line)
	}

	grid := container.NewGridWithColumns(2,
		labeled("Service", serviceVal),
		labeled("Enrollment", enrollVal),
		labeled("Agent ID", agentVal),
		labeled("Runtime", runtimeVal),
		labeled("Ingest", ingestVal),
		labeled("Detections", detectVal),
	)
	enrollBtn := widget.NewButtonWithIcon("Enroll device", theme.ConfirmIcon(), nil)
	enrollBtn.Importance = widget.HighImportance
	enrollRow := container.NewBorder(nil, nil, nil, enrollBtn, token)

	// The two views. Only one is ever visible, and which one is decided by
	// uiState alone — never by whether a subprocess exited non-zero.
	dashPane := container.NewVBox(grid, updatedVal)
	setupPane := container.NewVBox(
		widget.NewLabelWithStyle("Enrollment token", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		enrollRow,
	)

	applyStatus := func(st uiStatus) {
		stateVal.SetText(st.State.headline())
		stateDetail.SetText(st.State.detail())
		diagVal.SetText(describeSources(st))

		svc := dash(st.Service.String())
		if serviceHealthy(st.Service) {
			serviceVal.SetText("●  " + svc)
		} else {
			serviceVal.SetText("○  " + svc)
		}
		if st.Enrolled {
			enrollVal.SetText("●  enrolled")
		} else {
			enrollVal.SetText("○  not enrolled")
		}
		agentVal.SetText(dash(st.AgentID))
		ingestVal.SetText(dash(st.Ingest))
		rt := dash(st.Runtime)
		if st.Isolated {
			rt += "  (isolated)"
		}
		runtimeVal.SetText(rt)
		detectVal.SetText(fmt.Sprintf("%d", st.Detections))
		updatedVal.SetText("Status published " + dash(formatStamp(st.UpdatedAt)))

		if st.State.screen() == screenDashboard {
			setupPane.Hide()
			dashPane.Show()
		} else {
			dashPane.Hide()
			setupPane.Show()
		}
		if st.Error != "" {
			appendActivity("Status", st.Error, nil)
		}
	}

	setBusy := func(on bool) {
		if on {
			w.SetTitle("EDR Agent — working…")
		} else {
			w.SetTitle("EDR Agent")
		}
	}

	// refresh never runs loadStatus on the UI goroutine. It reads a local
	// file and may dial the control socket, and neither belongs on the
	// thread that draws the window.
	refresh := func() {
		setBusy(true)
		go func() {
			st := loadStatus()
			fyne.Do(func() {
				applyStatus(st)
				setBusy(false)
			})
		}()
	}

	runAction := func(title string, privileged bool, args ...string) {
		setBusy(true)
		go func() {
			var out string
			var err error
			if privileged {
				out, err = runEdrctlPrivileged(args...)
			} else {
				out, err = runEdrctl(args...)
			}
			if err != nil && strings.TrimSpace(out) == "" {
				out = friendlyExecError(err)
			}
			// The status re-read stays on this goroutine. Inside fyne.Do it
			// would be back on the UI thread, so every Start, Stop, Enroll and
			// connection test froze the window again once the action itself had
			// finished.
			st := loadStatus()
			fyne.Do(func() {
				appendActivity(title, out, err)
				applyStatus(st)
				setBusy(false)
			})
		}()
	}

	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
		refresh()
		appendActivity("Refresh", "Status updated.", nil)
	})
	testBtn := widget.NewButtonWithIcon("Test connection", theme.SearchIcon(), func() {
		runAction("Connection test", false, "test-connection")
	})
	startBtn := widget.NewButtonWithIcon("Start", theme.MediaPlayIcon(), func() {
		runAction("Start", true, "start")
	})
	stopBtn := widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), func() {
		runAction("Stop", true, "stop")
	})
	enrollBtn.OnTapped = func() {
		tok := strings.TrimSpace(token.Text)
		if tok == "" {
			appendActivity("Enroll", "Paste an enrollment token first.", nil)
			return
		}
		runAction("Enroll", true, "enroll", "--token", tok)
	}
	refreshBtn.Importance = widget.MediumImportance

	header := widget.NewRichTextFromMarkdown("## EDR Agent\nLive endpoint status, enrollment, and service control.")
	actions := container.NewGridWithColumns(4, refreshBtn, testBtn, startBtn, stopBtn)

	content := container.NewPadded(container.NewVBox(
		header,
		stateVal,
		stateDetail,
		dashPane,
		setupPane,
		diagVal,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Actions", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		actions,
		widget.NewLabelWithStyle("Activity", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		activity,
	))
	w.SetContent(content)
	refresh()

	go func() {
		t := time.NewTicker(4 * time.Second)
		defer t.Stop()
		for range t.C {
			st := loadStatus()
			fyne.Do(func() { applyStatus(st) })
		}
	}()

	w.ShowAndRun()
	return nil
}

// describeSources says where the view's data came from, so an operator can
// tell a stale status file from a socket this account may not open.
func describeSources(st uiStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Status file: %s (%s)", st.StatusFile, st.Availability)
	switch st.Control {
	case controlOK:
		b.WriteString("  ·  Control socket: connected")
	case controlDenied:
		b.WriteString("  ·  Control socket: present but not readable by this account (run edrctl with sudo for live counters)")
	default:
		b.WriteString("  ·  Control socket: unreachable")
	}
	if st.ControlDetail != "" && st.Control != controlOK {
		fmt.Fprintf(&b, " — %s", st.ControlDetail)
	}
	return b.String()
}

func formatStamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func labeled(title string, value *widget.Label) fyne.CanvasObject {
	h := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	return container.NewVBox(h, value)
}
