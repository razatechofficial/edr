package main

import "github.com/razatechofficial/edr/internal/platform"

func defaultConfigPath() string {
	return platform.ResolveConfigFile()
}
