//go:build linux

package xdrclient

// platformSystemUUID returns DMTF SMBIOS Type 1 System UUID (OCSF hw_info.uuid).
func platformSystemUUID() string {
	return readFileTrim(
		"/sys/class/dmi/id/product_uuid",
		"/sys/devices/virtual/dmi/id/product_uuid",
	)
}
