//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const darwinSensorApp = "/usr/local/libexec/edr-agent.app"

const darwinSensorInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>edr-agent</string>
	<key>CFBundleIdentifier</key>
	<string>com.razatech.edr-agent</string>
	<key>CFBundleName</key>
	<string>EDR Sensor</string>
	<key>CFBundleDisplayName</key>
	<string>EDR Sensor</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>LSUIElement</key>
	<true/>
	<key>LSBackgroundOnly</key>
	<true/>
	<key>LSMinimumSystemVersion</key>
	<string>12.0</string>
</dict>
</plist>
`

// wrapDarwinSensorApp puts the sensor in an .app so Full Disk Access lists
// "EDR Sensor" (CrowdStrike lists Falcon.app). A naked /usr/local/bin binary
// never appears; probing it from Setup.app makes Setup show up instead.
func wrapDarwinSensorApp(bin string) (string, error) {
	bin = filepath.Clean(bin)
	macos := filepath.Join(darwinSensorApp, "Contents", "MacOS")
	dst := filepath.Join(macos, "edr-agent")
	if err := os.MkdirAll(macos, 0755); err != nil {
		return bin, fmt.Errorf("sensor app: %w", err)
	}
	if bin != dst {
		if err := copyFile(bin, dst, 0755); err != nil {
			return bin, fmt.Errorf("sensor app binary: %w", err)
		}
	}
	plist := filepath.Join(darwinSensorApp, "Contents", "Info.plist")
	if err := os.WriteFile(plist, []byte(darwinSensorInfoPlist), 0644); err != nil {
		return dst, fmt.Errorf("sensor Info.plist: %w", err)
	}
	if err := os.WriteFile(filepath.Join(darwinSensorApp, "Contents", "PkgInfo"), []byte("APPL????"), 0644); err != nil {
		return dst, err
	}
	return dst, nil
}
