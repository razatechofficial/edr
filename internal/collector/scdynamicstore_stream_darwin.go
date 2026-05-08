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
static CFRunLoopRef g_scds_rl = NULL;

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

static int scds_run_loop_blocking(void) {
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
	g_scds_rl = CFRunLoopGetCurrent();
	CFRunLoopAddSource(g_scds_rl, src, kCFRunLoopDefaultMode);
	CFRunLoopRun();
	CFRunLoopRemoveSource(g_scds_rl, src, kCFRunLoopDefaultMode);
	CFRelease(src);
	CFRelease(store);
	g_scds_rl = NULL;
	return 0;
}

static void scds_request_stop(void) {
	CFRunLoopRef rl = g_scds_rl;
	if (rl != NULL) {
		CFRunLoopStop(rl);
	}
}

static int scds_get_event_count(void) { return g_scds_event_count; }

static char* scds_dup_last_key(void) {
	if (g_scds_last_key == NULL) return NULL;
	return strdup(g_scds_last_key);
}
*/
import "C"

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

// scdsRunLoopFn is swappable in tests (must run with runtime.LockOSThread in the caller).
var scdsRunLoopFn = func() (lastKey string, events int, errCode int) {
	code := int(C.scds_run_loop_blocking())
	ev := int(C.scds_get_event_count())
	var key *C.char
	if ev > 0 {
		key = C.scds_dup_last_key()
	}
	defer func() {
		if key != nil {
			C.free(unsafe.Pointer(key))
		}
	}()
	if key != nil {
		lastKey = C.GoString(key)
	}
	return lastKey, ev, code
}

var scdynamicstoreStopsTotal atomic.Uint64

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

// RunSCDynamicStoreRouteProbe runs a cgo-backed SCDynamicStore run loop until ctx is canceled
// or a bounded internal timeout triggers CFRunLoopStop.
func RunSCDynamicStoreRouteProbe(ctx context.Context, emit func(map[string]any)) {
	if emit == nil {
		return
	}
	if ctx.Err() != nil {
		return
	}
	subCtx, subCancel := context.WithTimeout(ctx, 3*time.Second)
	defer subCancel()

	type res struct {
		lk  string
		ev  int
		cod int
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		go func() {
			<-subCtx.Done()
			C.scds_request_stop()
		}()
		lk, ev, code := scdsRunLoopFn()
		scdynamicstoreStopsTotal.Add(1)
		ch <- res{lk: lk, ev: ev, cod: code}
	}()
	r := <-ch

	if r.cod != 0 {
		scutilFallbackProbe(ctx, emit, r.cod)
		return
	}
	out := map[string]any{
		"scdynamicstore_probe":         "cgo_stream",
		"scdynamicstore_stream_active": true,
		"scdynamicstore_events_total":  r.ev,
		"scdynamicstore_last_unix":     time.Now().Unix(),
		"scdynamicstore_thread_locked": true,
		"scdynamicstore_runloop_active": true,
		"scdynamicstore_stops_total":    scdynamicstoreStopsTotal.Load(),
	}
	if r.lk != "" {
		out["scdynamicstore_last_key"] = r.lk
	}
	emit(out)
}
