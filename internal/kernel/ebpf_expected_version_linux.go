//go:build linux

package kernel

import (
	_ "embed"
	"strings"
)

//go:embed ebpf_expected_version.txt
var ebpfExpectedVersionRaw string

func ebpfExpectedObjectVersion() string {
	return strings.TrimSpace(ebpfExpectedVersionRaw)
}
