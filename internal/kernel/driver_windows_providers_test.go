//go:build windows

package kernel

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/razatechofficial/edr/pkg/events"
	"golang.org/x/sys/windows"
)

func TestProvidersToStart_securityProvidersWhenEnabled(t *testing.T) {
	d, err := NewETWDriver("agent-test-12345678")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.SetPolicy(EventPolicy{
		ProcessEvents:          true,
		FileEvents:             true,
		NetworkEvents:          true,
		DNSEvents:              true,
		RegistryEvents:         true,
		ETWSecurityProviders:   true,
		ETWWMIActivity:         false,
		ETWPowerShellScript:    false,
		ETWNamedPipeHandles:    false,
		ETWBitsClient:          false,
		ETWTaskScheduler:       false,
	})
	want := map[string]windows.GUID{
		"AMSI":             amsiGUID,
		"CodeIntegrity":    codeIntegrityGUID,
		"AppLocker":        appLockerGUID,
		"Defender":         defenderETWGUID,
		"SecurityAuditing": securityAuditingGUID,
	}
	seen := map[string]bool{}
	for _, p := range d.providersToStart() {
		if w, ok := want[p.name]; ok {
			if p.guid != w {
				t.Fatalf("provider %s guid mismatch", p.name)
			}
			if p.eventType != events.EventSecurity {
				t.Fatalf("provider %s eventType=%s want security", p.name, p.eventType)
			}
			seen[p.name] = true
		}
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("missing provider %q in providersToStart", name)
		}
	}
}

func TestProvidersToStart_securityProvidersDisabled(t *testing.T) {
	d, err := NewETWDriver("agent-test-12345678")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.SetPolicy(EventPolicy{
		ProcessEvents:        true,
		FileEvents:           true,
		NetworkEvents:        true,
		DNSEvents:            true,
		RegistryEvents:       true,
		ETWSecurityProviders: false,
	})
	for _, p := range d.providersToStart() {
		switch p.name {
		case "AMSI", "CodeIntegrity", "AppLocker", "Defender", "SecurityAuditing":
			t.Fatalf("unexpected security provider %q when disabled", p.name)
		}
	}
}

// TestETWProviderGUIDsCanonical pins each provider GUID against its canonical
// manifest value. This catches accidental edits that revert to a zero or
// otherwise-bogus GUID (which silently disables event flow for that provider).
func TestETWProviderGUIDsCanonical(t *testing.T) {
	cases := []struct {
		name string
		got  windows.GUID
		want windows.GUID
	}{
		{"WMI-Activity", wmiActivityGUID, windows.GUID{
			Data1: 0x1418EF04, Data2: 0xB0B4, Data3: 0x4623,
			Data4: [8]byte{0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA},
		}},
		{"PowerShell", powershellGUID, windows.GUID{
			Data1: 0xA0C1853B, Data2: 0x5C40, Data3: 0x4B15,
			Data4: [8]byte{0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A},
		}},
		{"TaskScheduler", taskSchedulerGUID, windows.GUID{
			Data1: 0xDE7B24EA, Data2: 0x73C8, Data3: 0x4A09,
			Data4: [8]byte{0x98, 0x5D, 0x5B, 0xDA, 0xDC, 0xFA, 0x90, 0x17},
		}},
		{"BITS-Client", bitsClientGUID, windows.GUID{
			Data1: 0xEF1CC15B, Data2: 0x46C1, Data3: 0x414E,
			Data4: [8]byte{0xBB, 0x95, 0xE7, 0x6B, 0x07, 0x7B, 0xD5, 0x1E},
		}},
		{"Security-Auditing", securityAuditingGUID, windows.GUID{
			Data1: 0x54849625, Data2: 0x5478, Data3: 0x4994,
			Data4: [8]byte{0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D},
		}},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("provider %s GUID drift: got %+v want %+v", c.name, c.got, c.want)
		}
		if (c.got == windows.GUID{}) {
			t.Errorf("provider %s GUID is zero-value", c.name)
		}
	}
}

func TestDecodeAMSIETW_setsSubprovider(t *testing.T) {
	ud := []byte{0x48, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x00, 0x00} // "Hello"
	env := map[string]interface{}{}
	decodeAMSIETW(1101, ud, env)
	if env["etw_security_subprovider"] != "amsi" {
		t.Fatalf("amsi subprovider: %v", env["etw_security_subprovider"])
	}
	if env["message"] != "Hello" {
		t.Fatalf("message: %v", env["message"])
	}
}

// TestDecodeProcessUserData_CommandLine crafts a Kernel-Process v3+
// ProcessStart payload with both ImageName and CommandLine and asserts the
// decoder surfaces both as separate fields. ImageName / CommandLine are
// adjacent UTF-16LE NUL-terminated strings following the fixed-size header.
func TestDecodeProcessUserData_CommandLine(t *testing.T) {
	d, err := NewETWDriver("agent-test-12345678")
	if err != nil {
		t.Fatal(err)
	}
	encodeUTF16NUL := func(s string) []byte {
		out := make([]byte, 0, (len(s)+1)*2)
		for _, r := range s {
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], uint16(r))
			out = append(out, b[:]...)
		}
		out = append(out, 0, 0)
		return out
	}

	var ud []byte
	ud = append(ud, make([]byte, 24)...)
	binary.LittleEndian.PutUint32(ud[0:4], 4321)   // child_pid
	binary.LittleEndian.PutUint32(ud[12:16], 1234) // parent_pid
	binary.LittleEndian.PutUint32(ud[16:20], 1)    // session_id
	ud = append(ud, encodeUTF16NUL(`C:\Windows\System32\notepad.exe`)...)
	ud = append(ud, encodeUTF16NUL(`"C:\Windows\System32\notepad.exe" foo.txt`)...)

	rec := &etwEventRecord{}
	rec.EventHeader.EventDescriptor.Id = 1 // ProcessStart
	rec.UserDataLength = uint16(len(ud))
	rec.UserData = uintptr(unsafe.Pointer(&ud[0]))

	env := map[string]interface{}{}
	d.decodeProcessUserData(rec, env)

	if got := env["child_pid"]; got != uint32(4321) {
		t.Fatalf("child_pid: %v", got)
	}
	if got := env["parent_pid"]; got != uint32(1234) {
		t.Fatalf("parent_pid: %v", got)
	}
	if got := env["image_name"]; got != `C:\Windows\System32\notepad.exe` {
		t.Fatalf("image_name: %q", got)
	}
	if got := env["cmdline"]; got != `"C:\Windows\System32\notepad.exe" foo.txt` {
		t.Fatalf("cmdline: %q", got)
	}
}

// TestDecodeNetworkUserData_IPv6 builds a crafted TcpIp_V6_Header payload and
// checks the IPv6 branch of decodeNetworkUserData. The wire layout is:
//
//	PID(4) + size(4) + daddr(16) + saddr(16) + dport_BE(2) + sport_BE(2) = 44B.
func TestDecodeNetworkUserData_IPv6(t *testing.T) {
	d, err := NewETWDriver("agent-test-12345678")
	if err != nil {
		t.Fatal(err)
	}
	// Build wire bytes for ::1 -> 2001:db8::1 connect from PID 4242,
	// dport 443, sport 50000.
	ud := make([]byte, 44)
	binary.LittleEndian.PutUint32(ud[0:4], 4242)
	binary.LittleEndian.PutUint32(ud[4:8], 128)
	// daddr 2001:db8::1
	copy(ud[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	// saddr ::1
	copy(ud[24:40], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(ud[40:42], 443)
	binary.BigEndian.PutUint16(ud[42:44], 50000)

	rec := &etwEventRecord{}
	rec.EventHeader.EventDescriptor.Id = 26 // connect (IPv6)
	rec.UserDataLength = uint16(len(ud))
	rec.UserData = uintptr(unsafe.Pointer(&ud[0]))

	env := map[string]interface{}{}
	d.decodeNetworkUserData(rec, env)

	if got := env["ip_version"]; got != "6" {
		t.Fatalf("ip_version: %v want 6", got)
	}
	if got := env["pid"]; got != uint32(4242) {
		t.Fatalf("pid: %v want 4242", got)
	}
	if got := env["dst"]; got != "2001:db8::1" {
		t.Fatalf("dst: %v want 2001:db8::1", got)
	}
	if got := env["src"]; got != "::1" {
		t.Fatalf("src: %v want ::1", got)
	}
	if got := env["dest_port"]; got != 443 {
		t.Fatalf("dest_port: %v want 443", got)
	}
	if got := env["src_port"]; got != 50000 {
		t.Fatalf("src_port: %v want 50000", got)
	}
}

func TestShouldDropDuplicateKernelFileRW(t *testing.T) {
	d, err := NewETWDriver("agent-test-12345678")
	if err != nil {
		t.Fatal(err)
	}
	ud := make([]byte, 8)
	binary.LittleEndian.PutUint64(ud, 0xAABBCCDD)
	rec := &etwEventRecord{}
	rec.EventHeader.EventDescriptor.Id = kernelFileEvtReadID
	rec.UserDataLength = uint16(len(ud))
	rec.UserData = uintptr(unsafe.Pointer(&ud[0]))

	if drop := d.shouldDropDuplicateKernelFileRW(rec); drop {
		t.Fatal("first read event should not be dropped")
	}
	if drop := d.shouldDropDuplicateKernelFileRW(rec); !drop {
		t.Fatal("second read event should be dropped")
	}
	rec.EventHeader.EventDescriptor.Id = kernelFileEvtWriteID
	if drop := d.shouldDropDuplicateKernelFileRW(rec); drop {
		t.Fatal("first write event should not be dropped")
	}
	if drop := d.shouldDropDuplicateKernelFileRW(rec); !drop {
		t.Fatal("second write event should be dropped")
	}
}
