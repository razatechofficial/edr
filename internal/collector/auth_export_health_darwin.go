//go:build darwin

package collector

func authLogPathEmptyHealthMessage() string {
	return "no_auth_log_path; enable monitoring.darwin_auth_unified_log when /var/log/system.log is unreadable or install log(1)"
}
