//go:build windows

package main

// P2-17 — Apply process-level mitigation policies to the EDR agent at
// startup so that the kernel itself prevents the most common in-process
// tampering vectors before any third-party code (DLL hijack, JIT-spray,
// remote thread + WriteProcessMemory shellcode) can run.
//
// The mitigations applied below are documented under
// `PROCESS_MITIGATION_*_POLICY` in the Microsoft SDK header
// processthreadsapi.h. The values map 1:1 to the kernel
// `ProcessMitigationPolicy` field. We call SetProcessMitigationPolicy
// for each policy independently because the API rejects the entire
// 64-bit flag word if any reserved bit is set in a future kernel.
//
// Policies enabled (in order of importance):
//
//   1. ProcessDynamicCodePolicy
//      Blocks any thread from allocating or running JIT-generated code
//      (NtProtectVirtualMemory with PAGE_EXECUTE on a writable region).
//      Cobalt Strike / Sliver / brute-force shellcode injection rely
//      on this — denying it removes the entire class.
//
//   2. ProcessSignaturePolicy ("MicrosoftSignedOnly")
//      Blocks loading of any DLL that is not signed by Microsoft. Set
//      to "audit" by default so an operator can roll it out without
//      breaking integrated AV that ships unsigned helpers; the operator
//      flips the enforcement bit via config once they have validated.
//
//   3. ProcessImageLoadPolicy
//      Blocks remote-image and low-mandatory-label image loads — i.e.
//      a low-integrity attacker cannot drop a DLL into a writable
//      directory and force-load it via SetWindowsHookEx.
//
//   4. ProcessExtensionPointDisablePolicy
//      Blocks legacy extension points (AppInit_DLLs, IME, Winsock LSP).
//      Pure hardening; no compatibility risk for an agent process.
//
// SetProcessMitigationPolicy is irreversible for the current process,
// so the agent must apply it at the earliest possible moment before
// loading user-supplied modules. We call applyProcessMitigations()
// from runAgent() right after config is loaded — config loading uses
// only static stdlib code so the policies cannot trip the agent on
// itself.

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"go.uber.org/zap"
)

// PROCESS_MITIGATION_POLICY enum (subset).
const (
	processDEPPolicy                    uint32 = 0
	processASLRPolicy                   uint32 = 1
	processDynamicCodePolicy            uint32 = 2
	processStrictHandleCheckPolicy      uint32 = 3
	processSystemCallDisablePolicy      uint32 = 4
	processMitigationOptionsMask        uint32 = 5
	processExtensionPointDisablePolicy  uint32 = 6
	processControlFlowGuardPolicy       uint32 = 7
	processSignaturePolicy              uint32 = 8
	processFontDisablePolicy            uint32 = 9
	processImageLoadPolicy              uint32 = 10
)

// PROCESS_MITIGATION_DYNAMIC_CODE_POLICY flags. The kernel reads a
// 32-bit DWORD; bits above ProhibitDynamicCode are reserved.
type processMitigationDynamicCodePolicy struct {
	Flags uint32
}

const (
	prohibitDynamicCode            uint32 = 0x00000001
	allowThreadOptOut              uint32 = 0x00000002
	allowRemoteDowngrade           uint32 = 0x00000004
	auditProhibitDynamicCode       uint32 = 0x00000008
)

type processMitigationBinarySignaturePolicy struct {
	Flags uint32
}

const (
	microsoftSignedOnly       uint32 = 0x00000001
	storeSignedOnly           uint32 = 0x00000002
	mitigationOptIn           uint32 = 0x00000004
	auditMicrosoftSignedOnly  uint32 = 0x00000008
)

type processMitigationImageLoadPolicy struct {
	Flags uint32
}

const (
	noRemoteImages            uint32 = 0x00000001
	noLowMandatoryLabelImages uint32 = 0x00000002
	preferSystem32Images      uint32 = 0x00000004
	auditNoRemoteImages       uint32 = 0x00000008
	auditNoLowMandatoryLabel  uint32 = 0x00000010
)

type processMitigationExtensionPointDisablePolicy struct {
	Flags uint32
}

const disableExtensionPoints uint32 = 0x00000001

var (
	procSetProcessMitigationPolicy = windows.NewLazySystemDLL("kernel32.dll").
		NewProc("SetProcessMitigationPolicy")
)

// applyProcessMitigations enables the hardening policies on the
// current process. Failures are logged and reported in the boot
// posture, but never abort startup — older Windows builds (pre-1709)
// or systems with conflicting AV may legitimately reject some flags.
func applyProcessMitigations(logger *zap.Logger) map[string]any {
	result := map[string]any{
		"dynamic_code":          false,
		"image_load":            false,
		"extension_point":       false,
		"signature_audit":       false,
	}

	// 1. Dynamic code: prohibit + allow opt-out so a sub-component
	// that legitimately needs RWX (e.g. embedded Lua) can request it
	// via SetThreadInformation(ThreadDynamicCodePolicy). The opt-out
	// must be explicit per-thread, so a vanilla shellcode injection
	// still fails.
	dyn := processMitigationDynamicCodePolicy{
		Flags: prohibitDynamicCode | allowThreadOptOut,
	}
	if err := setMitigation(processDynamicCodePolicy, unsafe.Pointer(&dyn), unsafe.Sizeof(dyn)); err != nil {
		logger.Warn("SetProcessMitigationPolicy(DynamicCode) failed",
			zap.Error(err))
		result["dynamic_code_error"] = err.Error()
	} else {
		result["dynamic_code"] = true
	}

	// 2. Signature policy: start in audit mode. Enforcement is opt-in
	// because legitimate third-party AV interop ships unsigned DLLs
	// and would otherwise be killed before they can register their
	// minifilter.
	sig := processMitigationBinarySignaturePolicy{
		Flags: auditMicrosoftSignedOnly,
	}
	if err := setMitigation(processSignaturePolicy, unsafe.Pointer(&sig), unsafe.Sizeof(sig)); err != nil {
		logger.Warn("SetProcessMitigationPolicy(Signature) failed",
			zap.Error(err))
		result["signature_audit_error"] = err.Error()
	} else {
		result["signature_audit"] = true
	}

	// 3. Image load: block remote and low-integrity images.
	img := processMitigationImageLoadPolicy{
		Flags: noRemoteImages | noLowMandatoryLabelImages | preferSystem32Images,
	}
	if err := setMitigation(processImageLoadPolicy, unsafe.Pointer(&img), unsafe.Sizeof(img)); err != nil {
		logger.Warn("SetProcessMitigationPolicy(ImageLoad) failed",
			zap.Error(err))
		result["image_load_error"] = err.Error()
	} else {
		result["image_load"] = true
	}

	// 4. Extension point: kill AppInit / IME / LSP injection.
	ep := processMitigationExtensionPointDisablePolicy{
		Flags: disableExtensionPoints,
	}
	if err := setMitigation(processExtensionPointDisablePolicy, unsafe.Pointer(&ep), unsafe.Sizeof(ep)); err != nil {
		logger.Warn("SetProcessMitigationPolicy(ExtensionPoint) failed",
			zap.Error(err))
		result["extension_point_error"] = err.Error()
	} else {
		result["extension_point"] = true
	}

	logger.Info("process mitigation policies applied",
		zap.Bool("dynamic_code", result["dynamic_code"].(bool)),
		zap.Bool("image_load", result["image_load"].(bool)),
		zap.Bool("extension_point", result["extension_point"].(bool)),
		zap.Bool("signature_audit", result["signature_audit"].(bool)),
	)
	return result
}

func setMitigation(policy uint32, ptr unsafe.Pointer, size uintptr) error {
	r1, _, e1 := procSetProcessMitigationPolicy.Call(
		uintptr(policy),
		uintptr(ptr),
		size,
	)
	if r1 == 0 {
		if e1 != nil && e1 != windows.ERROR_SUCCESS {
			return e1
		}
		return windows.ERROR_INVALID_PARAMETER
	}
	return nil
}
