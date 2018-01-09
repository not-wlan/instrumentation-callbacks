#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#include <Winternl.h>
#include <DbgHelp.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <cstdint>
#include <functional>
#pragma comment(lib, "ntdll.lib")
#pragma comment (lib, "imagehlp.lib")

#ifdef _WIN64
#define CALLBACK_VERSION 0
#else
#define CALLBACK_VERSION 1
#endif

using CallbackFn = void(*)();

using PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION = struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	CallbackFn Callback;
};

using MEMORY_INFORMATION_CLASS = enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
};

extern "C" NTSTATUS DECLSPEC_IMPORT NTAPI NtSetInformationProcess(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
extern "C" NTSTATUS DECLSPEC_IMPORT NTAPI NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);

extern "C" VOID medium(VOID);
extern "C" uintptr_t hook(uintptr_t R10, uintptr_t RAX/* ... */);


