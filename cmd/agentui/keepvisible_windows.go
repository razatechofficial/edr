//go:build windows

package main

func keepConsoleVisible() bool {
	return windowsProductIsServer() || windowsIsRemoteSession()
}
