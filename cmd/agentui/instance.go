package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	uiShowMu sync.Mutex
	uiShow   func()
)

func setUIShow(fn func()) {
	uiShowMu.Lock()
	uiShow = fn
	uiShowMu.Unlock()
}

func invokeUIShow() {
	uiShowMu.Lock()
	fn := uiShow
	uiShowMu.Unlock()
	if fn != nil {
		fn()
	}
}

// instancePortFile is per entry point so Setup never activates the installed
// console (and the console never swallows a Setup launch). Chrome / Falcon /
// WiX Modify keep the installer and the product UI on separate locks.
func instancePortFile() string {
	return filepath.Join(os.TempDir(), instancePortName(flagSetup))
}

func instancePortName(setup bool) string {
	if setup {
		return "com.razatech.edr.setup.port"
	}
	return "com.razatech.edr.console.port"
}

// claimUIInstance holds a localhost listener so a second launch (Applications /
// Dock) activates the existing process instead of spawning a second tray icon.
// If activate is true, a peer is told to show the decorated dashboard.
func claimUIInstance(activate bool) (release func(), exclusive bool) {
	portFile := instancePortFile()
	if b, err := os.ReadFile(portFile); err == nil {
		addr := strings.TrimSpace(string(b))
		if addr != "" {
			conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err == nil {
				if activate {
					_, _ = conn.Write([]byte("show\n"))
				}
				_ = conn.Close()
				return nil, false
			}
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return func() {}, true
	}
	_ = os.WriteFile(portFile, []byte(ln.Addr().String()), 0600)
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				line, _ := bufio.NewReader(c).ReadString('\n')
				if strings.TrimSpace(line) == "show" {
					invokeUIShow()
				}
			}(conn)
		}
	}()
	return func() {
		close(done)
		_ = ln.Close()
		_ = os.Remove(portFile)
	}, true
}
