/* SPDX-License-Identifier: MIT */
/*
 * EDR WDM process-protection driver (ObRegisterCallbacks).
 * Strips PROCESS_TERMINATE / VM_WRITE / SUSPEND on registered agent PIDs.
 *
 * Requires WHQL attestation signing before production load on Secure Boot systems.
 * Pair with AM-PPL signed user-mode service for full self-preservation.
 *
 * Build: Windows Driver Kit (WDK) — see platform/windows/build-drivers.ps1
 */

#include <ntddk.h>
#include <wdm.h>
#include "../include/edr_ioctl.h"

typedef struct _EDR_CONTEXT {
	HANDLE              ProtectedPids[EDR_MAX_PROTECTED_PIDS];
	ULONG               ProtectedPidCount;
	FAST_MUTEX          PidLock;
	PVOID               ObHandle;
	PDEVICE_OBJECT      DeviceObject;
	UNICODE_STRING      SymlinkName;
} EDR_CONTEXT, *PEDR_CONTEXT;

static EDR_CONTEXT g_Ctx;

static BOOLEAN EdrIsPidProtected(HANDLE Pid)
{
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&g_Ctx.PidLock);
	for (ULONG i = 0; i < g_Ctx.ProtectedPidCount; i++) {
		if (g_Ctx.ProtectedPids[i] == Pid) {
			found = TRUE;
			break;
		}
	}
	ExReleaseFastMutex(&g_Ctx.PidLock);
	return found;
}

static OB_PREOP_CALLBACK_STATUS
EdrPreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OpInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OpInfo->ObjectType != *PsProcessType)
		return OB_PREOP_SUCCESS;

	PEPROCESS process = (PEPROCESS)OpInfo->Object;
	HANDLE pid = PsGetProcessId(process);

	if (!EdrIsPidProtected(pid))
		return OB_PREOP_SUCCESS;

	HANDLE callerPid = PsGetCurrentProcessId();
	if (callerPid == pid)
		return OB_PREOP_SUCCESS;

	ACCESS_MASK deny = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME |
			   PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
			   PROCESS_CREATE_THREAD;

	if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
		OpInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~deny;
	else if (OpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~deny;

	return OB_PREOP_SUCCESS;
}

static NTSTATUS EdrRegisterObCallbacks(void)
{
	OB_CALLBACK_REGISTRATION cbReg;
	OB_OPERATION_REGISTRATION opReg;

	RtlZeroMemory(&cbReg, sizeof(cbReg));
	RtlZeroMemory(&opReg, sizeof(opReg));

	opReg.ObjectType     = PsProcessType;
	opReg.Operations     = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation   = EdrPreOperationCallback;
	opReg.PostOperation  = NULL;

	cbReg.Version                    = OB_FLT_REGISTRATION_VERSION;
	cbReg.OperationRegistrationCount = 1;
	cbReg.OperationRegistration      = &opReg;

	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, L"385200.5");
	cbReg.Altitude = altitude;
	cbReg.RegistrationContext = NULL;

	return ObRegisterCallbacks(&cbReg, &g_Ctx.ObHandle);
}

static NTSTATUS
EdrDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG info = 0;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_EDR_ADD_PROTECTED_PID: {
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		HANDLE pid = *(HANDLE *)Irp->AssociatedIrp.SystemBuffer;

		ExAcquireFastMutex(&g_Ctx.PidLock);
		if (g_Ctx.ProtectedPidCount < EDR_MAX_PROTECTED_PIDS) {
			g_Ctx.ProtectedPids[g_Ctx.ProtectedPidCount++] = pid;
		} else {
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		ExReleaseFastMutex(&g_Ctx.PidLock);
		break;
	}
	case IOCTL_EDR_REMOVE_PROTECTED_PID: {
		if (irpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		HANDLE pid = *(HANDLE *)Irp->AssociatedIrp.SystemBuffer;

		ExAcquireFastMutex(&g_Ctx.PidLock);
		for (ULONG i = 0; i < g_Ctx.ProtectedPidCount; i++) {
			if (g_Ctx.ProtectedPids[i] == pid) {
				g_Ctx.ProtectedPids[i] = g_Ctx.ProtectedPids[g_Ctx.ProtectedPidCount - 1];
				g_Ctx.ProtectedPidCount--;
				break;
			}
		}
		ExReleaseFastMutex(&g_Ctx.PidLock);
		break;
	}
	case IOCTL_EDR_CLEAR_PROTECTED_PIDS:
		ExAcquireFastMutex(&g_Ctx.PidLock);
		g_Ctx.ProtectedPidCount = 0;
		ExReleaseFastMutex(&g_Ctx.PidLock);
		break;
	case IOCTL_EDR_GET_STATUS: {
		if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(EDR_PROTECT_STATUS)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		PEDR_PROTECT_STATUS out = (PEDR_PROTECT_STATUS)Irp->AssociatedIrp.SystemBuffer;
		RtlZeroMemory(out, sizeof(*out));
		ExAcquireFastMutex(&g_Ctx.PidLock);
		out->ProtectedPidCount = g_Ctx.ProtectedPidCount;
		ExReleaseFastMutex(&g_Ctx.PidLock);
		out->ObCallbacksRegistered = (g_Ctx.ObHandle != NULL) ? 1 : 0;
		info = sizeof(EDR_PROTECT_STATUS);
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

static NTSTATUS
EdrCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if (g_Ctx.ObHandle) {
		ObUnRegisterCallbacks(g_Ctx.ObHandle);
		g_Ctx.ObHandle = NULL;
	}

	IoDeleteSymbolicLink(&g_Ctx.SymlinkName);
	if (g_Ctx.DeviceObject)
		IoDeleteDevice(g_Ctx.DeviceObject);
}

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	UNICODE_STRING devName;

	RtlZeroMemory(&g_Ctx, sizeof(g_Ctx));
	ExInitializeFastMutex(&g_Ctx.PidLock);

	RtlInitUnicodeString(&devName, EDR_DEVICE_NAME);
	RtlInitUnicodeString(&g_Ctx.SymlinkName, EDR_SYMLINK_NAME);

	status = IoCreateDevice(
		DriverObject,
		0,
		&devName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_Ctx.DeviceObject);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&g_Ctx.SymlinkName, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(g_Ctx.DeviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE]         = EdrCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]          = EdrCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EdrDeviceControl;
	DriverObject->DriverUnload                          = DriverUnload;

	status = EdrRegisterObCallbacks();
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&g_Ctx.SymlinkName);
		IoDeleteDevice(g_Ctx.DeviceObject);
		return status;
	}

	return STATUS_SUCCESS;
}
