// Package hostperm is the per-OS permission and persistence catalog for the
// EDR Agent console, installer, and edrctl.
//
// Industry mapping (CrowdStrike Falcon / Microsoft Defender / SentinelOne):
//   - Sensor is a machine-wide service (LaunchDaemon / Windows Service / systemd),
//     not a per-user login item. It must start at boot for every account.
//   - The operator UI may auto-start at login for all users (LaunchAgent in
//     /Library/LaunchAgents, HKLM Run, /etc/xdg/autostart).
//   - macOS Full Disk Access is granted to the sensor binary (TCC), not the UI.
//   - Endpoint Security may run in-process; a System Extension row is only
//     required when macOS has registered one for this product.
//   - Revocation is re-checked on every launch (NIST SI-4 continuous monitoring).
package hostperm

// Status is a single catalog row.
type Status string

const (
	StatusOK      Status = "ok"
	StatusAction  Status = "action"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
	StatusNA      Status = "na"
)

// Item is one permission or persistence check shown in the desktop catalog.
type Item struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Doing         string `json:"doing,omitempty"`
	Detail        string `json:"detail,omitempty"`
	Guide         string `json:"guide,omitempty"`
	SettingsLabel string `json:"settings_label,omitempty"`
	Status        Status `json:"status"`
	Required      bool   `json:"required"`
}

// Report is the evaluated catalog for this host.
type Report struct {
	OS          string `json:"os"`
	Items       []Item `json:"items"`
	AllRequired bool   `json:"all_required"`
	NeedsAction bool   `json:"needs_action"`
}

// Catalog IDs — keep stable; the UI and tests key on these.
const (
	IDFDA       = "fda"
	IDSysExt    = "sysext"
	IDNetExt    = "netext"
	IDFirewall  = "firewall"
	IDCaps      = "caps"
	IDService   = "service"
	IDBootStart = "boot"
	IDLoginUI   = "login_ui"
	IDSpool     = "spool"
)

// SensorBinaryHint is the path operators should enable in TCC / FDA lists.
func SensorBinaryHint() string {
	return sensorBinaryHint()
}
