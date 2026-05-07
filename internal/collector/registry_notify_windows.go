//go:build windows

package collector

import (
	"context"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	regNotifyChangeName    = uint32(0x00000001)
	regNotifyChangeLastSet = uint32(0x00000004)
)

var advapiReg = windows.NewLazyDLL("advapi32.dll")
var procRegNotifyChangeKeyValueW = advapiReg.NewProc("RegNotifyChangeKeyValue")

func regNotifyChangeKeyValueW(hKey windows.Handle, watchSubtree bool, notifyFilter uint32, event windows.Handle, asynchronous bool) error {
	advapiReg.Load()
	var st uintptr
	if watchSubtree {
		st = 1
	}
	var async uintptr
	if asynchronous {
		async = 1
	}
	r0, _, e := procRegNotifyChangeKeyValueW.Call(
		uintptr(hKey),
		st,
		uintptr(notifyFilter),
		uintptr(event),
		async,
	)
	if r0 == 0 {
		return nil
	}
	if e != nil {
		return e
	}
	return windows.Errno(r0)
}

// Registry notify coordination fields live on RegistryCollector (registry_collector_windows.go).

// StartRegistryNotifyLoop arms RegNotifyChangeKeyValue per watched path (one goroutine each).
func (rc *RegistryCollector) StartRegistryNotifyLoop(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	rc.notifyRunning.Store(true)
	for _, keyPath := range rc.watchKeys {
		p := keyPath
		go rc.watchRegistryKeyNotify(ctx, p)
	}
}

func (rc *RegistryCollector) watchRegistryKeyNotify(ctx context.Context, keyPath string) {
	filter := regNotifyChangeName | regNotifyChangeLastSet
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		root, sub, ok := parseRegistryRoot(keyPath)
		if !ok {
			return
		}
		k, err := registry.OpenKey(root, sub, registry.READ)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		ev, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			_ = k.Close()
			time.Sleep(time.Second)
			continue
		}
		h := windows.Handle(k)
		// Subtree=true so IFEO/Services/BHO subkey churn wakes the collector.
		err = regNotifyChangeKeyValueW(h, true, filter, ev, true)
		if err != nil {
			windows.CloseHandle(ev)
			_ = k.Close()
			time.Sleep(time.Second)
			continue
		}
		// Wait up to 5s so we can observe ctx cancellation via loop iteration.
		w, err := windows.WaitForSingleObject(ev, 5000)
		_ = k.Close()
		_ = windows.CloseHandle(ev)
		if err != nil {
			continue
		}
		if w != windows.WAIT_OBJECT_0 {
			continue
		}
		rc.notifyPending.Store(true)
		rc.notifyWakeups.Add(1)
	}
}
