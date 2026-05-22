/* SPDX-License-Identifier: MIT */
/*
 * Shared IOCTL definitions for EDR Windows kernel companions.
 * Keep in sync with internal/kernel/wdm_ioctl_windows.go.
 */
#pragma once

#include <winioctl.h>

#define EDR_DEVICE_NAME  L"\\Device\\EdrProtect"
#define EDR_SYMLINK_NAME L"\\DosDevices\\EdrProtect"
#define EDR_USER_DEVICE  L"\\\\.\\EdrProtect"

#define IOCTL_EDR_ADD_PROTECTED_PID    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EDR_REMOVE_PROTECTED_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EDR_CLEAR_PROTECTED_PIDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EDR_GET_STATUS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define EDR_MAX_PROTECTED_PIDS 256

typedef struct _EDR_PROTECT_STATUS {
	ULONG ProtectedPidCount;
	ULONG ObCallbacksRegistered;
	ULONG Reserved;
} EDR_PROTECT_STATUS, *PEDR_PROTECT_STATUS;
