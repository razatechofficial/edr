/* SPDX-License-Identifier: MIT */
/*
 * EDR Early Launch Anti-Malware (ELAM) driver scaffold.
 *
 * Production requirements (Microsoft Hardware Dev Center):
 *   1. MVI (Microsoft Virus Initiative) membership
 *   2. WHQL / attestation signing for boot-start ELAM catalog
 *   3. INF Class=EarlyLaunch with boot-start service
 *
 * This stub registers the driver load path; extend with boot-driver
 * classification callbacks once signing pipeline is active.
 *
 * Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware
 */

#include <ntddk.h>
#include <wdm.h>

#define EDR_ELAM_POOL_TAG 'malE'

DRIVER_UNLOAD EdrElamUnload;

VOID
EdrElamUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = EdrElamUnload;

	/*
	 * TODO (post-MVI signing):
	 *   - Register boot-start driver classification callback
	 *   - Publish good/bad/unknown classifications to ELAM manager
	 *   - Tie publisher thumbprint to AM-PPL user-mode service cert
	 */
	return STATUS_SUCCESS;
}
