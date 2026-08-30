package xdrclient

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// CollectDeviceIdentity gathers stable + contextual device facts for CSR binding.
// MachineID prefers SMBIOS/IOPlatform UUID (OCSF hw_info.uuid); serial/model/
// manufacturer follow IEEE 802.1AR / TCG DevID subject identity. Volatile fields
// (IP, timezone, timestamp) are enrollment context + Register/PKI labels.
func CollectDeviceIdentity(agentID, machineID, agentVer, enrollmentToken string) DeviceIdentity {
	host := Hostname()
	mfr := readManufacturer()
	model := readProductModel()
	serial := readHardwareSerial()
	mid := ResolveMachineID(machineID)
	id := DeviceIdentity{
		AgentID:           agentID,
		Hostname:          host,
		MachineID:         mid,
		OSFamily:          runtime.GOOS,
		OSVersion:         runtime.GOARCH,
		AgentVer:          agentVer,
		Manufacturer:      mfr,
		ProductModel:      model,
		HardwareSerial:    serial,
		PrimaryIP:         primaryIPv4(),
		Timezone:          localTimezone(),
		EnrollTimestamp:   time.Now().UTC().Format(time.RFC3339),
		EnrollmentTokenFP: enrollmentTokenFingerprint(enrollmentToken),
	}
	if id.AgentVer == "" {
		id.AgentVer = "dev"
	}
	// Prefer hardware serial as certificate serialNumber (802.1AR); fall back to machine_id.
	if id.HardwareSerial == "" {
		id.HardwareSerial = mid
	}
	if id.Manufacturer == "" {
		id.Manufacturer = "unknown"
	}
	if id.ProductModel == "" {
		id.ProductModel = runtime.GOOS + "-" + runtime.GOARCH
	}
	return id
}

// Labels returns Register/PKI tag map (includes volatile enrollment context).
func (id DeviceIdentity) Labels() map[string]string {
	m := map[string]string{
		"source":              "edr-agent",
		"manufacturer":        id.Manufacturer,
		"product_model":       id.ProductModel,
		"hardware_serial":     id.HardwareSerial,
		"machine_id":          id.MachineID,
		"os_family":           id.OSFamily,
		"os_arch":             id.OSVersion,
		"agent_version":       id.AgentVer,
		"timezone":            id.Timezone,
		"enroll_timestamp":    id.EnrollTimestamp,
		"enrollment_token_fp": id.EnrollmentTokenFP,
	}
	if id.PrimaryIP != "" {
		m["primary_ip"] = id.PrimaryIP
	}
	if id.Hostname != "" {
		m["hostname"] = id.Hostname
	}
	return m
}

func enrollmentTokenFingerprint(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func localTimezone() string {
	name, off := time.Now().Zone()
	if name != "" && name != "Local" {
		return name
	}
	sign := "+"
	if off < 0 {
		sign = "-"
		off = -off
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, off/3600, (off%3600)/60)
}

func primaryIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

func readFileTrim(paths ...string) string {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if s := strings.TrimSpace(string(b)); s != "" && !strings.EqualFold(s, "None") {
			return s
		}
	}
	return ""
}

func runTrim(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	hideConsole(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if v := strings.TrimSpace(line); v != "" {
			return v
		}
	}
	return ""
}
