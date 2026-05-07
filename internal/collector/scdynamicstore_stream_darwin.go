//go:build darwin && cgo && !nosec

package collector

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

static int g_scds_event_count = 0;
static char* g_scds_last_key = NULL;

static void scds_reset_globals(void) {
	g_scds_event_count = 0;
	if (g_scds_last_key != NULL) {
		free(g_scds_last_key);
		g_scds_last_key = NULL;
	}
}

static void scds_set_last_key(CFStringRef s) {
	if (s == NULL) return;
	char buf[512];
	if (!CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8)) return;
	if (g_scds_last_key != NULL) free(g_scds_last_key);
	g_scds_last_key = strdup(buf);
}

static void scds_callback(SCDynamicStoreRef store, CFArrayRef changedKeys, void *info) {
	(void)store; (void)info;
	if (changedKeys == NULL) return;
	CFIndex n = CFArrayGetCount(changedKeys);
	if (n <= 0) return;
	g_scds_event_count += (int)n;
	CFTypeRef v = CFArrayGetValueAtIndex(changedKeys, n-1);
	if (v && CFGetTypeID(v) == CFStringGetTypeID()) {
		scds_set_last_key((CFStringRef)v);
	}
}

static int scds_watch_once(double seconds, char** out_key, int* out_count) {
	*out_key = NULL;
	*out_count = 0;
	scds_reset_globals();
	SCDynamicStoreContext ctx = {0, NULL, NULL, NULL, NULL};
	SCDynamicStoreRef store = SCDynamicStoreCreate(NULL, CFSTR("edr.scdynamicstore.stream"), scds_callback, &ctx);
	if (store == NULL) return -1;

	CFStringRef keysV[2];
	keysV[0] = CFSTR("State:/Network/Global/IPv4");
	keysV[1] = CFSTR("State:/Network/Global/DNS");
	CFArrayRef keys = CFArrayCreate(NULL, (const void **)keysV, 2, &kCFTypeArrayCallBacks);
	CFStringRef patsV[1];
	patsV[0] = CFSTR("State:/Network/Service/[^/]+/IPv4");
	CFArrayRef pats = CFArrayCreate(NULL, (const void **)patsV, 1, &kCFTypeArrayCallBacks);
	Boolean ok = SCDynamicStoreSetNotificationKeys(store, keys, pats);
	CFRelease(keys);
	CFRelease(pats);
	if (!ok) {
		CFRelease(store);
		return -2;
	}
	CFRunLoopSourceRef src = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
	if (src == NULL) {
		CFRelease(store);
		return -3;
	}
	CFRunLoopRef rl = CFRunLoopGetCurrent();
	CFRunLoopAddSource(rl, src, kCFRunLoopDefaultMode);
	CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, false);
	CFRunLoopRemoveSource(rl, src, kCFRunLoopDefaultMode);
	CFRelease(src);
	CFRelease(store);
	*out_count = g_scds_event_count;
	if (g_scds_last_key != NULL) {
		*out_key = strdup(g_scds_last_key);
	}
	return 0;
}
*/
import "C"

import (
	"context"
	"os/exec"
	"strings"
	"time"
	"unsafe"
)

var scdsWatchOnceFn = func(seconds float64) (lastKey string, count int, errCode int) {
	var key *C.char
	var ccount C.int
	code := int(C.scds_watch_once(C.double(seconds), &key, &ccount))
	defer func() {
		if key != nil {
			C.free(unsafe.Pointer(key))
		}
	}()
	if key != nil {
		lastKey = C.GoString(key)
	}
	return lastKey, int(ccount), code
}

func scutilFallbackProbe(ctx context.Context, emit func(map[string]any), code int) {
	c := exec.CommandContext(ctx, "scutil", "--nc", "list")
	out, err := c.CombinedOutput()
	if err != nil {
		emit(map[string]any{
			"scdynamicstore_probe":         "error",
			"scdynamicstore_stream_active": false,
			"scdynamicstore_error_code":    code,
			"detail":                       err.Error(),
		})
		return
	}
	emit(map[string]any{
		"scdynamicstore_probe":         "scutil_nc_list",
		"scdynamicstore_stream_active": false,
		"scdynamicstore_error_code":    code,
		"lines":                        len(strings.Split(string(out), "\n")),
	})
}

// RunSCDynamicStoreRouteProbe runs a bounded cgo-backed SCDynamicStore callback watch.
// On callback setup/runtime failures, it gracefully falls back to scutil probing.
func RunSCDynamicStoreRouteProbe(ctx context.Context, emit func(map[string]any)) {
	if emit == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}
	lastKey, events, code := scdsWatchOnceFn(0.75)
	if code != 0 {
		scutilFallbackProbe(ctx, emit, code)
		return
	}
	out := map[string]any{
		"scdynamicstore_probe":         "cgo_stream",
		"scdynamicstore_stream_active": true,
		"scdynamicstore_events_total":  events,
		"scdynamicstore_last_unix":     time.Now().Unix(),
	}
	if lastKey != "" {
		out["scdynamicstore_last_key"] = lastKey
	}
	emit(out)
}

