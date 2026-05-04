//go:build !linux && !darwin

package collector

func authLogPathEmptyHealthMessage() string {
	return "no_auth_log_path"
}
