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
		"AMSI":            amsiGUID,
		"CodeIntegrity":   codeIntegrityGUID,
		"AppLocker":       appLockerGUID,
		"Defender":        defenderETWGUID,
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
		case "AMSI", "CodeIntegrity", "AppLocker", "Defender":
			t.Fatalf("unexpected security provider %q when disabled", p.name)
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
