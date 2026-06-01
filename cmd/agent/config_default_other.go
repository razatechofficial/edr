//go:build !windows

package main

func defaultConfigPath() string {
	return "configs/agent.example.yaml"
}
