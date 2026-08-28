//go:build darwin && cgo

package keystore

// System.keychain trusted-app ACLs still require SecKeychainOpen,
// SecTrustedApplicationCreateFromPath, and SecAccessCreate. Apple marked
// those deprecated in 10.10 with no SecItem replacement for LaunchDaemon
// identity, so this file silences -Wdeprecated-declarations.

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#cgo CFLAGS: -Wno-deprecated-declarations
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static CFStringRef cfstr(const char *s) {
	return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}

static void append_trusted(CFMutableArrayRef arr, const char *path) {
	if (arr == NULL || path == NULL || path[0] == 0) {
		return;
	}
	if (access(path, X_OK) != 0) {
		return;
	}
	SecTrustedApplicationRef app = NULL;
	if (SecTrustedApplicationCreateFromPath(path, &app) == errSecSuccess && app != NULL) {
		CFArrayAppendValue(arr, app);
		CFRelease(app);
	}
}

static CFArrayRef trusted_apps(const char *extra_app) {
	CFMutableArrayRef arr = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
	if (arr == NULL) {
		return NULL;
	}
	append_trusted(arr, "/usr/local/libexec/edr-agent.app/Contents/MacOS/edr-agent");
	append_trusted(arr, "/usr/local/bin/edrctl");
	append_trusted(arr, "/usr/local/bin/edr");
	append_trusted(arr, "/Applications/EDR Agent.app/Contents/MacOS/edrctl");
	append_trusted(arr, "/Applications/EDR Agent.app/Contents/MacOS/edr-agent-ui");
	append_trusted(arr, extra_app);
	return arr;
}

static SecKeychainRef system_kc(void) {
	if (geteuid() != 0) {
		return NULL;
	}
	SecKeychainRef kc = NULL;
	if (SecKeychainOpen("/Library/Keychains/System.keychain", &kc) != errSecSuccess) {
		return NULL;
	}
	return kc;
}

static void kc_delete(CFStringRef svc, CFStringRef acct, SecKeychainRef kc) {
	const void *keys[4];
	const void *vals[4];
	int n = 0;
	keys[n] = kSecClass; vals[n] = kSecClassGenericPassword; n++;
	keys[n] = kSecAttrService; vals[n] = svc; n++;
	keys[n] = kSecAttrAccount; vals[n] = acct; n++;
	if (kc != NULL) {
		keys[n] = kSecUseKeychain; vals[n] = kc; n++;
	}
	CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, n,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (q) {
		SecItemDelete(q);
		CFRelease(q);
	}
}

static OSStatus kc_add(CFStringRef svc, CFStringRef acct, CFDataRef cfData, SecAccessRef access, SecKeychainRef kc) {
	const void *keys[8];
	const void *vals[8];
	int n = 0;
	keys[n] = kSecClass; vals[n] = kSecClassGenericPassword; n++;
	keys[n] = kSecAttrService; vals[n] = svc; n++;
	keys[n] = kSecAttrAccount; vals[n] = acct; n++;
	keys[n] = kSecValueData; vals[n] = cfData; n++;
	keys[n] = kSecAttrAccessible; vals[n] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly; n++;
	keys[n] = kSecAttrSynchronizable; vals[n] = kCFBooleanFalse; n++;
	if (access != NULL) {
		keys[n] = kSecAttrAccess; vals[n] = access; n++;
	}
	if (kc != NULL) {
		keys[n] = kSecUseKeychain; vals[n] = kc; n++;
	}
	CFDictionaryRef addQ = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, n,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = errSecParam;
	if (addQ) {
		st = SecItemAdd(addQ, NULL);
		CFRelease(addQ);
	}
	return st;
}

// kc_upsert stores bytes as a generic password (ThisDeviceOnly).
// As root it also writes System.keychain so the LaunchDaemon can read the item,
// and grants the agent + edrctl binaries access (items are otherwise ACL'd
// to the creating executable only).
static OSStatus kc_upsert(const char *service, const char *account, const void *data, size_t len, const char *extra_app) {
	CFStringRef svc = cfstr(service);
	CFStringRef acct = cfstr(account);
	if (svc == NULL || acct == NULL) {
		if (svc) CFRelease(svc);
		if (acct) CFRelease(acct);
		return errSecParam;
	}

	SecKeychainRef sys = system_kc();
	kc_delete(svc, acct, NULL);
	if (sys != NULL) {
		kc_delete(svc, acct, sys);
	}

	CFDataRef cfData = CFDataCreate(kCFAllocatorDefault, data, (CFIndex)len);
	if (cfData == NULL) {
		if (sys) CFRelease(sys);
		CFRelease(svc);
		CFRelease(acct);
		return errSecAllocate;
	}

	SecAccessRef access = NULL;
	CFArrayRef trusted = trusted_apps(extra_app);
	if (trusted != NULL && CFArrayGetCount(trusted) > 0) {
		SecAccessCreate(CFSTR("EDR Agent identity"), trusted, &access);
	}
	if (trusted) CFRelease(trusted);

	OSStatus st = errSecParam;
	if (sys != NULL) {
		st = kc_add(svc, acct, cfData, access, sys);
	}
	if (st != errSecSuccess) {
		st = kc_add(svc, acct, cfData, access, NULL);
	}

	if (access) CFRelease(access);
	if (sys) CFRelease(sys);
	CFRelease(cfData);
	CFRelease(svc);
	CFRelease(acct);
	return st;
}

static OSStatus kc_copy(const char *service, const char *account, SecKeychainRef kc, int wantData, CFTypeRef *result) {
	CFStringRef svc = cfstr(service);
	CFStringRef acct = cfstr(account);
	if (svc == NULL || acct == NULL) {
		if (svc) CFRelease(svc);
		if (acct) CFRelease(acct);
		return errSecParam;
	}
	const void *keys[7];
	const void *vals[7];
	int n = 0;
	keys[n] = kSecClass; vals[n] = kSecClassGenericPassword; n++;
	keys[n] = kSecAttrService; vals[n] = svc; n++;
	keys[n] = kSecAttrAccount; vals[n] = acct; n++;
	keys[n] = kSecMatchLimit; vals[n] = kSecMatchLimitOne; n++;
	if (wantData) {
		keys[n] = kSecReturnData; vals[n] = kCFBooleanTrue; n++;
	}
	if (kc != NULL) {
		keys[n] = kSecMatchSearchList;
		CFArrayRef list = CFArrayCreate(kCFAllocatorDefault, (const void **)&kc, 1, &kCFTypeArrayCallBacks);
		vals[n] = list; n++;
		CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, n,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		OSStatus st = errSecParam;
		if (q) {
			st = SecItemCopyMatching(q, result);
			CFRelease(q);
		}
		CFRelease(list);
		CFRelease(svc);
		CFRelease(acct);
		return st;
	}
	CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, n,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = errSecParam;
	if (q) {
		st = SecItemCopyMatching(q, result);
		CFRelease(q);
	}
	CFRelease(svc);
	CFRelease(acct);
	return st;
}

static OSStatus kc_load(const char *service, const char *account, void **out, size_t *outLen) {
	CFTypeRef result = NULL;
	OSStatus st = kc_copy(service, account, NULL, 1, &result);
	if (st != errSecSuccess || result == NULL) {
		SecKeychainRef sys = system_kc();
		if (sys != NULL) {
			st = kc_copy(service, account, sys, 1, &result);
			CFRelease(sys);
		}
	}
	if (st != errSecSuccess || result == NULL) {
		return st != errSecSuccess ? st : errSecItemNotFound;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex n = CFDataGetLength(data);
	void *buf = malloc((size_t)n);
	if (buf == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	memcpy(buf, CFDataGetBytePtr(data), (size_t)n);
	CFRelease(result);
	*out = buf;
	*outLen = (size_t)n;
	return errSecSuccess;
}

static OSStatus kc_has(const char *service, const char *account) {
	OSStatus st = kc_copy(service, account, NULL, 0, NULL);
	if (st == errSecSuccess) {
		return st;
	}
	SecKeychainRef sys = system_kc();
	if (sys != NULL) {
		st = kc_copy(service, account, sys, 0, NULL);
		CFRelease(sys);
	}
	return st;
}

static void kc_clear(const char *service, const char *account) {
	CFStringRef svc = cfstr(service);
	CFStringRef acct = cfstr(account);
	if (svc == NULL || acct == NULL) {
		if (svc) CFRelease(svc);
		if (acct) CFRelease(acct);
		return;
	}
	kc_delete(svc, acct, NULL);
	SecKeychainRef sys = system_kc();
	if (sys != NULL) {
		kc_delete(svc, acct, sys);
		CFRelease(sys);
	}
	CFRelease(svc);
	CFRelease(acct);
}
*/
import "C"

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

const kcService = "com.razatech.edr.xdr-identity"

type keychainStore struct {
	dir string // scopes Keychain accounts + CA/enrollment.json sidecar
}

func newKeychainStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &keychainStore{dir: dir}, nil
}

func (s *keychainStore) Name() string { return BackendKeychain }

// account names are scoped by cert_dir so multiple agents/tests don't collide.
func (s *keychainStore) acct(kind string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(s.dir)))
	return kind + ":" + hex.EncodeToString(sum[:8])
}

func (s *keychainStore) Save(m Material) error {
	if err := kcUpsert(s.acct("agent-private-key"), m.KeyPEM); err != nil {
		return fmt.Errorf("keychain save key: %w", err)
	}
	if err := kcUpsert(s.acct("agent-certificate"), m.CertPEM); err != nil {
		return fmt.Errorf("keychain save cert: %w", err)
	}
	if len(m.CSRPEM) > 0 {
		if err := kcUpsert(s.acct("agent-csr"), m.CSRPEM); err != nil {
			return fmt.Errorf("keychain save csr: %w", err)
		}
	}
	// Remove any leftover plaintext / sealed file copies of secrets.
	for _, name := range []string{"agent.key", "agent.crt", "agent.csr", "agent.key.enc", "agent.crt.enc", "agent.csr.enc"} {
		_ = os.Remove(filepath.Join(s.dir, name))
	}
	return nil
}

func (s *keychainStore) LoadKeyPEM() ([]byte, error) {
	return kcLoad(s.acct("agent-private-key"))
}
func (s *keychainStore) LoadCertPEM() ([]byte, error) {
	return kcLoad(s.acct("agent-certificate"))
}
func (s *keychainStore) LoadCSRPEM() ([]byte, error) {
	return kcLoad(s.acct("agent-csr"))
}

func (s *keychainStore) Has() bool {
	return kcHas(s.acct("agent-private-key")) && kcHas(s.acct("agent-certificate"))
}

func (s *keychainStore) Clear() error {
	for _, kind := range []string{"agent-private-key", "agent-certificate", "agent-csr"} {
		kcClear(s.acct(kind))
	}
	return nil
}

func kcClear(account string) {
	svc := C.CString(kcService)
	acct := C.CString(account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	C.kc_clear(svc, acct)
}

func kcHas(account string) bool {
	svc := C.CString(kcService)
	acct := C.CString(account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	return C.kc_has(svc, acct) == C.errSecSuccess
}

func kcUpsert(account string, data []byte) error {
	svc := C.CString(kcService)
	acct := C.CString(account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	extra := ""
	if exe, err := os.Executable(); err == nil {
		extra = exe
	}
	cextra := C.CString(extra)
	defer C.free(unsafe.Pointer(cextra))
	var ptr unsafe.Pointer
	if len(data) > 0 {
		ptr = unsafe.Pointer(&data[0])
	}
	st := C.kc_upsert(svc, acct, ptr, C.size_t(len(data)), cextra)
	if st != C.errSecSuccess {
		return fmt.Errorf("SecItemAdd status=%d", int(st))
	}
	return nil
}

func kcLoad(account string) ([]byte, error) {
	svc := C.CString(kcService)
	acct := C.CString(account)
	defer C.free(unsafe.Pointer(svc))
	defer C.free(unsafe.Pointer(acct))
	var out unsafe.Pointer
	var n C.size_t
	st := C.kc_load(svc, acct, &out, &n)
	if st != C.errSecSuccess {
		return nil, fmt.Errorf("SecItemCopyMatching status=%d", int(st))
	}
	defer C.free(out)
	return C.GoBytes(out, C.int(n)), nil
}
