#pragma once

#include <Windows.h>
//#include "Structs.h"

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// Syscalls declarations
// ------------------------------------------------------------------------

// Windows 7 SP1 / Server 2008 R2 specific Syscalls
EXTERN_C NTSTATUS NtCreateFile7SP1(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
EXTERN_C NTSTATUS NtCreateSection7SP1(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
EXTERN_C NTSTATUS NtMapViewOfSection7SP1(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
EXTERN_C NTSTATUS NtProtectVirtualMemory7SP1(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS NtUnmapViewOfSection7SP1(HANDLE ProcessHandle, PVOID BaseAddress);
EXTERN_C NTSTATUS NtClose7SP1(HANDLE Handle);

// Windows 8 / Server 2012 specific Syscalls
EXTERN_C NTSTATUS NtCreateFile80(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
EXTERN_C NTSTATUS NtCreateSection80(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
EXTERN_C NTSTATUS NtMapViewOfSection80(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
EXTERN_C NTSTATUS NtProtectVirtualMemory80(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS NtUnmapViewOfSection80(HANDLE ProcessHandle, PVOID BaseAddress);
EXTERN_C NTSTATUS NtClose80(HANDLE Handle);

// Windows 8.1 / Server 2012 R2 specific Syscalls
EXTERN_C NTSTATUS NtCreateFile81(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
EXTERN_C NTSTATUS NtCreateSection81(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
EXTERN_C NTSTATUS NtMapViewOfSection81(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
EXTERN_C NTSTATUS NtProtectVirtualMemory81(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS NtUnmapViewOfSection81(HANDLE ProcessHandle, PVOID BaseAddress);
EXTERN_C NTSTATUS NtClose81(HANDLE Handle);

// Windows 10 / Server 2016 specific Syscalls
EXTERN_C NTSTATUS NtCreateFile10(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
EXTERN_C NTSTATUS NtCreateSection10(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
EXTERN_C NTSTATUS NtMapViewOfSection10(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
EXTERN_C NTSTATUS NtProtectVirtualMemory10(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
EXTERN_C NTSTATUS NtUnmapViewOfSection10(HANDLE ProcessHandle, PVOID BaseAddress);
EXTERN_C NTSTATUS NtClose10(HANDLE Handle);

//BRS:Comodo start
EXTERN_C NTSTATUS ZOP10(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

/*

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

NTSTATUS(*ZwOpenProcess)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	);

//BRS:Comodo einde
*/
// Nt Function declarations
// ------------------------------------------------------------------------



NTSTATUS(*NtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	);

NTSTATUS(*NtCreateSection)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER     MaximumSize,
	ULONG              SectionPageProtection,
	ULONG              AllocationAttributes,
	HANDLE             FileHandle
	);

NTSTATUS(*NtMapViewOfSection)(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID           *BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);

NTSTATUS(*NtProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);

NTSTATUS(*NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
	);

NTSTATUS(*NtClose)(
	HANDLE Handle
	);

// To resolve direct syscalls by reading OS version from PEB
// ------------------------------------------------------------------------

BOOL resolve_syscalls() {
	// Init some important stuff
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;

	// Get pointer to the TEB
	pTIB = (PNT_TIB)__readgsqword(0x30);
	pTEB = (PTEB)pTIB->Self;

	// Get pointer to the PEB
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return FALSE;
	}

	// Resolve the syscalls
    // Windows 10 / Server 2016
	if (pPEB->OSMajorVersion == 10 && pPEB->OSMinorVersion == 0) {
		NtCreateFile = &NtCreateFile10;
		NtCreateSection = &NtCreateSection10;
		NtMapViewOfSection = &NtMapViewOfSection10;
		NtProtectVirtualMemory = &NtProtectVirtualMemory10;
		NtUnmapViewOfSection = &NtUnmapViewOfSection10;
		NtClose = &NtClose10;
	}
	// Windows 7 SP1 / Server 2008 R2
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 1 && pPEB->OSBuildNumber == 7601) {
		NtCreateFile = &NtCreateFile7SP1;
		NtCreateSection = &NtCreateSection7SP1;
		NtMapViewOfSection = &NtMapViewOfSection7SP1;
		NtProtectVirtualMemory = &NtProtectVirtualMemory7SP1;
		NtUnmapViewOfSection = &NtUnmapViewOfSection7SP1;
		NtClose = &NtClose7SP1;
	}
	// Windows 8 / Server 2012
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 2) {
		NtCreateFile = &NtCreateFile80;
		NtCreateSection = &NtCreateSection80;
		NtMapViewOfSection = &NtMapViewOfSection80;
		NtProtectVirtualMemory = &NtProtectVirtualMemory80;
		NtUnmapViewOfSection = &NtUnmapViewOfSection80;
		NtClose = &NtClose80;
	}
	// Windows 8.1 / Server 2012 R2
	else if (pPEB->OSMajorVersion == 6 && pPEB->OSMinorVersion == 3) {
		NtCreateFile = &NtCreateFile81;
		NtCreateSection = &NtCreateSection81;
		NtMapViewOfSection = &NtMapViewOfSection81;
		NtProtectVirtualMemory = &NtProtectVirtualMemory81;
		NtUnmapViewOfSection = &NtUnmapViewOfSection81;
		NtClose = &NtClose81;
	}
	// Not any of the above
	else {
		return FALSE;
	}

	return TRUE;
}