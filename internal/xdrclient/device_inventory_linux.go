//go:build linux

package xdrclient

func readHardwareSerial() string {
	return readFileTrim(
		"/sys/class/dmi/id/product_serial",
		"/sys/devices/virtual/dmi/id/product_serial",
		"/etc/machine-id",
	)
}

func readProductModel() string {
	return readFileTrim(
		"/sys/class/dmi/id/product_name",
		"/sys/devices/virtual/dmi/id/product_name",
		"/sys/class/dmi/id/product_version",
	)
}

func readManufacturer() string {
	return readFileTrim(
		"/sys/class/dmi/id/sys_vendor",
		"/sys/devices/virtual/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor",
	)
}
