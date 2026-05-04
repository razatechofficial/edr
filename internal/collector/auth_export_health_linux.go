//go:build linux

package collector

func authLogPathEmptyHealthMessage() string {
	if journalAuthEligible() {
		return "no_auth_log_path; enable monitoring.journald_auth or linux_auth_auto_journal when journal is available"
	}
	return "no_auth_log_path;journal_ineligible"
}
