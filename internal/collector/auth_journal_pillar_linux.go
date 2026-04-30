//go:build linux

package collector

type journalAuthPillar struct {
	*streamingRunCollector
}

func newJournalAuthPillarCollector(j *JournaldSource, streamMaxEPS int) *journalAuthPillar {
	raw := newStreamingRunCollector("__auth_journal", 256, streamMaxEPS, j.Run, func() map[string]any {
		return journalAuthPillarHealth(j)
	})
	return &journalAuthPillar{streamingRunCollector: raw}
}

func (a *journalAuthPillar) Name() string { return "auth" }

func journalAuthPillarHealth(j *JournaldSource) map[string]any {
	h := j.ExportMonitoringHealth()
	if h == nil {
		src := MonitoringSource{
			Name:   "auth",
			OS:     "linux",
			Source: "journald",
			Status: "healthy",
			Notes:  "journalctl ssh/sudo ladder",
		}
		return src.ToMap()
	}
	h["name"] = "auth"
	h["source"] = "journald"
	if _, ok := h["notes"]; !ok {
		h["notes"] = "journalctl ssh/sudo ladder"
	}
	return h
}
