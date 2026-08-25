package main

import (
	"strings"

	"github.com/razatechofficial/edr/internal/xdrclient"
)

// enrollmentHostFromDomain maps a management apex (xdr.averox.com) to
// enroll.<apex>:443. Operators never type ingest or a URL list.
func enrollmentHostFromDomain(apex string) string {
	s := strings.TrimSpace(apex)
	if s == "" {
		return xdrclient.DefaultEnrollmentHost
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "enroll.") {
		if _, _, err := splitHostPortLoose(s); err != nil {
			return s + ":443"
		}
		return s
	}
	if _, _, err := splitHostPortLoose(s); err == nil {
		return s
	}
	return "enroll." + s + ":443"
}

func splitHostPortLoose(s string) (host, port string, err error) {
	if strings.Count(s, ":") != 1 {
		return "", "", errNoPort
	}
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", errNoPort
	}
	return s[:i], s[i+1:], nil
}

type portErr string

func (e portErr) Error() string { return string(e) }

const errNoPort portErr = "no port"

func domainLooksInvalid(value string) bool {
	s := strings.TrimSpace(value)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, " /") || strings.Contains(s, "://") {
		return true
	}
	if strings.HasPrefix(s, "enroll.") || strings.HasPrefix(s, "ingest.") {
		return true
	}
	if strings.Contains(s, ":") {
		return true
	}
	if !strings.Contains(s, ".") {
		return true
	}
	return false
}
