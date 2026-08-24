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
	w.Resize(fyne.NewSize(760, 620))
	w.SetMaster()

	serviceVal := widget.NewLabel("…")
	enrollVal := widget.NewLabel("…")
	agentVal := widget.NewLabel("…")
	ingestVal := widget.NewLabel("…")
	runtimeVal := widget.NewLabel("…")
	detectVal := widget.NewLabel("…")
	updatedVal := widget.NewLabel("…")
	for _, l := range []*widget.Label{serviceVal, enrollVal, agentVal, ingestVal, runtimeVal, detectVal, updatedVal} {
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

	applyStatus := func(st operatorStatus) {
		svc := dash(st.Service)
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
		updatedVal.SetText(dash(st.UpdatedAt))
		if st.Error != "" {
			appendActivity("Status", st.Error, nil)
		}
	}

	refresh := func() {
		applyStatus(loadStatus())
	}

	setBusy := func(on bool) {
		if on {
			w.SetTitle("EDR Agent — working…")
		} else {
			w.SetTitle("EDR Agent")
		}
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
			fyne.Do(func() {
				appendActivity(title, out, err)
				applyStatus(loadStatus())
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
	enrollBtn := widget.NewButtonWithIcon("Enroll device", theme.ConfirmIcon(), func() {
		tok := strings.TrimSpace(token.Text)
		if tok == "" {
			appendActivity("Enroll", "Paste an enrollment token first.", nil)
			return
		}
		runAction("Enroll", true, "enroll", "--token", tok)
	})
	enrollBtn.Importance = widget.HighImportance
	refreshBtn.Importance = widget.MediumImportance

	header := widget.NewRichTextFromMarkdown("## EDR Agent\nLive endpoint status, enrollment, and service control.")
	grid := container.NewGridWithColumns(2,
		labeled("Service", serviceVal),
		labeled("Enrollment", enrollVal),
		labeled("Agent ID", agentVal),
		labeled("Runtime", runtimeVal),
		labeled("Ingest", ingestVal),
		labeled("Detections", detectVal),
	)
	actions := container.NewGridWithColumns(4, refreshBtn, testBtn, startBtn, stopBtn)
	enrollRow := container.NewBorder(nil, nil, nil, enrollBtn, token)

	content := container.NewPadded(container.NewVBox(
		header,
		grid,
		updatedVal,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Actions", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		actions,
		widget.NewLabelWithStyle("Enrollment token", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		enrollRow,
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

func labeled(title string, value *widget.Label) fyne.CanvasObject {
	h := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	return container.NewVBox(h, value)
}
