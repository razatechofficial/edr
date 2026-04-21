//go:build darwin && cgo

package kernel

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework EndpointSecurity

#include <EndpointSecurity/EndpointSecurity.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static int esf_is_exec_event(int t) {
	return t == (int)ES_EVENT_TYPE_AUTH_EXEC || t == (int)ES_EVENT_TYPE_NOTIFY_EXEC;
}

// Fills teamBuf (NUL-terminated) and cdhexBuf (lowercase hex of first CD hash).
static void esf_signing_info(const char *utf8Path, char *teamBuf, size_t teamLen,
	char *cdhexBuf, size_t cdhexLen, uint32_t *outFlags) {
	if (!utf8Path || utf8Path[0] == '\0') {
		return;
	}
	if (teamBuf && teamLen > 0) {
		teamBuf[0] = '\0';
	}
	if (cdhexBuf && cdhexLen > 0) {
		cdhexBuf[0] = '\0';
	}
	if (outFlags) {
		*outFlags = 0;
	}

	CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
		(const UInt8 *)utf8Path, strlen(utf8Path), false);
	if (!url) {
		return;
	}

	SecStaticCodeRef code = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (st != errSecSuccess || code == NULL) {
		return;
	}

	CFDictionaryRef info = NULL;
	st = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
	CFRelease(code);
	if (st != errSecSuccess || info == NULL) {
		return;
	}

	CFTypeRef tid = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
	if (tid && CFGetTypeID(tid) == CFStringGetTypeID() && teamBuf && teamLen > 0) {
		CFStringGetCString((CFStringRef)tid, teamBuf, (CFIndex)teamLen, kCFStringEncodingUTF8);
	}

	CFTypeRef hashes = CFDictionaryGetValue(info, kSecCodeInfoCdHashes);
	if (hashes && CFGetTypeID(hashes) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)hashes) > 0 &&
		cdhexBuf && cdhexLen > 2) {
		CFDataRef d = (CFDataRef)CFArrayGetValueAtIndex((CFArrayRef)hashes, 0);
		if (d) {
			const uint8_t *b = CFDataGetBytePtr(d);
			CFIndex n = CFDataGetLength(d);
			static const char *hex = "0123456789abcdef";
			size_t pos = 0;
			for (CFIndex i = 0; i < n && pos + 2 < cdhexLen; i++) {
				cdhexBuf[pos++] = hex[(b[i] >> 4) & 0xf];
				cdhexBuf[pos++] = hex[b[i] & 0xf];
			}
			cdhexBuf[pos] = '\0';
		}
	}

	CFTypeRef fl = CFDictionaryGetValue(info, kSecCodeInfoFlags);
	if (fl && CFGetTypeID(fl) == CFNumberGetTypeID() && outFlags) {
		int64_t fv = 0;
		if (CFNumberGetValue((CFNumberRef)fl, kCFNumberSInt64Type, &fv)) {
			*outFlags = (uint32_t)fv;
		}
	}

	CFRelease(info);
}
*/
import "C"

import "unsafe"

// esfExecSigningInfo returns Team ID, CD hash hex, and SecCode flags for an on-disk path.
func esfIsExecEvent(eventType int) bool {
	return C.esf_is_exec_event(C.int(eventType)) != 0
}

func esfExecSigningInfo(path string) (teamID, cdHash string, flags uint32) {
	if path == "" {
		return "", "", 0
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var team [256]C.char
	var cdh [128]C.char
	var fl C.uint32_t
	C.esf_signing_info(cpath, &team[0], C.size_t(len(team)), &cdh[0], C.size_t(len(cdh)), &fl)
	return C.GoString(&team[0]), C.GoString(&cdh[0]), uint32(fl)
}
