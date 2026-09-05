//go:build !windows

package main

func uiLog(string, ...any) {}

func uiAlert(string, string) {}
