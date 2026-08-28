//go:build darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit -framework Foundation
#import <AppKit/AppKit.h>

extern void goEDRBecameActive(void);

static void edrRegisterActive(void) {
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		[[NSNotificationCenter defaultCenter]
			addObserverForName:NSApplicationDidBecomeActiveNotification
			object:nil
			queue:nil
			usingBlock:^(NSNotification *n) { goEDRBecameActive(); }];
	});
}

static void edrPlaceWindow(void *nswindow, int width, int height, int nearCursor, int flyout) {
	if (nswindow == NULL) {
		return;
	}
	NSWindow *w = (NSWindow *)nswindow;
	if (flyout) {
		[w setHasShadow:YES];
		[w setOpaque:YES];
		[w setBackgroundColor:[NSColor colorWithCalibratedRed:0x1C/255.0 green:0x1C/255.0 blue:0x1E/255.0 alpha:1.0]];
		if (w.contentView != nil) {
			w.contentView.wantsLayer = YES;
			w.contentView.layer.cornerRadius = 20.0;
			w.contentView.layer.masksToBounds = YES;
		}
	}
	NSScreen *screen = w.screen;
	if (screen == nil) {
		screen = [NSScreen mainScreen];
	}
	NSRect vf = [screen visibleFrame];
	CGFloat ww = (CGFloat)width;
	CGFloat hh = (CGFloat)height;
	CGFloat x;
	CGFloat y;
	if (nearCursor) {
		NSPoint p = [NSEvent mouseLocation];
		x = p.x - ww + 24.0;
		y = p.y - hh - 8.0;
	} else {
		x = NSMaxX(vf) - ww - 16.0;
		y = NSMaxY(vf) - hh - 8.0;
	}
	if (x < NSMinX(vf) + 8.0) {
		x = NSMinX(vf) + 8.0;
	}
	if (x + ww > NSMaxX(vf) - 8.0) {
		x = NSMaxX(vf) - ww - 8.0;
	}
	if (y < NSMinY(vf) + 8.0) {
		y = NSMinY(vf) + 8.0;
	}
	if (y + hh > NSMaxY(vf) - 8.0) {
		y = NSMaxY(vf) - hh - 8.0;
	}
	[w setFrame:NSMakeRect(x, y, ww, hh) display:YES];
}

static void edrBringFront(void *nswindow) {
	if (nswindow == NULL) {
		return;
	}
	NSWindow *w = (NSWindow *)nswindow;
	[w deminiaturize:nil];
	[NSApp activateIgnoringOtherApps:YES];
	[w makeKeyAndOrderFront:nil];
	[w orderFrontRegardless];
}

static void edrMoveWindow(void *nswindow, float dx, float dy) {
	if (nswindow == NULL) {
		return;
	}
	NSWindow *w = (NSWindow *)nswindow;
	NSRect f = [w frame];
	f.origin.x += (CGFloat)dx;
	f.origin.y -= (CGFloat)dy;
	[w setFrame:f display:YES];
}
*/
import "C"

import (
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
)

//export goEDRBecameActive
func goEDRBecameActive() {
	invokeBecomeActive()
}

func registerAppActivate() {
	C.edrRegisterActive()
}

func nativeNSWindow(win fyne.Window) unsafe.Pointer {
	var p unsafe.Pointer
	nw, ok := win.(driver.NativeWindow)
	if !ok {
		return nil
	}
	nw.RunNative(func(ctx any) {
		mc, ok := ctx.(driver.MacWindowContext)
		if ok && mc.NSWindow != 0 {
			p = unsafe.Pointer(mc.NSWindow)
		}
	})
	return p
}

func placeNearTray(win fyne.Window, width, height float32, nearCursor, flyout bool) {
	p := nativeNSWindow(win)
	if p == nil {
		return
	}
	nc, fl := C.int(0), C.int(0)
	if nearCursor {
		nc = 1
	}
	if flyout {
		fl = 1
	}
	C.edrPlaceWindow(p, C.int(width), C.int(height), nc, fl)
}

func moveNativeWindow(win fyne.Window, dx, dy float32) {
	p := nativeNSWindow(win)
	if p == nil {
		return
	}
	C.edrMoveWindow(p, C.float(dx), C.float(dy))
}

func bringNativeWindow(win fyne.Window) {
	p := nativeNSWindow(win)
	if p == nil {
		return
	}
	C.edrBringFront(p)
}
