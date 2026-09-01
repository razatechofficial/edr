//go:build !darwin

package hostperm

func revealSensorForFDA() {}

func SensorFDAItemPath() string { return sensorBinaryHint() }

func confirmFDAViaApp() bool { return false }
