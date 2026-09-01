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
		[[NSProcessInfo processInfo] disableAutomaticTermination:@"EDR Agent menu bar"];
		[[NSProcessInfo processInfo] disableSuddenTermination];
		[[NSNotificationCenter defaultCenter]
			addObserverForName:NSApplicationDidBecomeActiveNotification
			object:nil
			queue:nil
			usingBlock:^(NSNotification *n) { goEDRBecameActive(); }];
	});
}

static void edrStayInMenuBar(void) {
	[[NSProcessInfo processInfo] disableAutomaticTermination:@"EDR Agent menu bar"];
	[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
}

static void edrPlaceWindow(void *nswindow, int width, int height, int nearCursor, int flyout) {
	if (nswindow == NULL) {
		return;
	}
	NSWindow *w = (NSWindow *)nswindow;
	[w setAnimationBehavior:NSWindowAnimationBehaviorNone];
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
	[w setFrame:NSMakeRect(x, y, ww, hh) display:YES animate:NO];
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
	[w setFrameOrigin:NSMakePoint(f.origin.x + (CGFloat)dx, f.origin.y - (CGFloat)dy)];
}

static void edrResizeKeepTop(void *nswindow, int width, int height) {
	if (nswindow == NULL) {
		return;
	}
	NSWindow *w = (NSWindow *)nswindow;
	[w setAnimationBehavior:NSWindowAnimationBehaviorNone];
	NSRect f = [w frame];
	CGFloat ww = (CGFloat)width;
	CGFloat hh = (CGFloat)height;
	CGFloat dw = f.size.width - ww;
	CGFloat dh = f.size.height - hh;
	if (dw < 0) {
		dw = -dw;
	}
	if (dh < 0) {
		dh = -dh;
	}
	if (dw < 0.5 && dh < 0.5) {
		return;
	}
	NSScreen *screen = w.screen;
	if (screen == nil) {
		screen = [NSScreen mainScreen];
	}
	NSRect vf = [screen visibleFrame];
	if (hh > vf.size.height - 16.0) {
		hh = vf.size.height - 16.0;
	}
	CGFloat y = NSMaxY(f) - hh;
	if (y < NSMinY(vf)) {
		y = NSMinY(vf);
	}
	[w setFrame:NSMakeRect(f.origin.x, y, ww, hh) display:NO animate:NO];
}

static void edrStartWindowDrag(void *nswindow) {
	if (nswindow == NULL) {
		return;
	}
	NSWindow *w = (NSWindow *)nswindow;
	NSEvent *e = [NSApp currentEvent];
	if (e == nil) {
		return;
	}
	NSEventType t = [e type];
	if (t != NSEventTypeLeftMouseDown && t != NSEventTypeLeftMouseDragged) {
		return;
	}
	[w performWindowDragWithEvent:e];
}
*/
import "C"

import (
	"sync"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
)

var (
	nsWinMu sync.Mutex
	nsWins  = map[fyne.Window]unsafe.Pointer{}
)

//export goEDRBecameActive
func goEDRBecameActive() {
	invokeBecomeActive()
}

func registerAppActivate() {
	C.edrRegisterActive()
}

func stayInMenuBar() {
	C.edrStayInMenuBar()
}

func nativeNSWindow(win fyne.Window) unsafe.Pointer {
	if win == nil {
		return nil
	}
	nsWinMu.Lock()
	if p, ok := nsWins[win]; ok && p != nil {
		nsWinMu.Unlock()
		return p
	}
	nsWinMu.Unlock()

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
	if p == nil {
		return nil
	}
	nsWinMu.Lock()
	nsWins[win] = p
	nsWinMu.Unlock()
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

func nativeWorkLogical(win fyne.Window) (float32, float32) {
	if win == nil || win.Canvas() == nil {
		return 0, 0
	}
	if scr := win.Canvas().Size(); scr.Height > 0 {
		// Canvas size is the window, not the display. Fall back to a
		// conservative laptop work height so sheets stay on-screen.
		_ = scr
	}
	return 0, 0
}

func nativeResizeKeepTop(win fyne.Window, width, height float32) bool {
	p := nativeNSWindow(win)
	if p == nil {
		return false
	}
	C.edrResizeKeepTop(p, C.int(width), C.int(height))
	return true
}

func startNativeWindowDrag(win fyne.Window) bool {
	p := nativeNSWindow(win)
	if p == nil {
		return false
	}
	C.edrStartWindowDrag(p)
	return true
}

func bringNativeWindow(win fyne.Window) {
	p := nativeNSWindow(win)
	if p == nil {
		return
	}
	C.edrBringFront(p)
}
