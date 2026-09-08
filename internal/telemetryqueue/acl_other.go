//go:build !windows

package telemetryqueue

func prepareQueueDir(string) {}

func relaxQueuePath(string) {}
