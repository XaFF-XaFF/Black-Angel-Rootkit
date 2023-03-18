#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "debug.hpp"

#define DEVICE_NAME(name) L"\\Device\\"#name
#define DOSDEVICE_NAME(name) L"\\DosDevices\\"#name
#define DRIVER_NAME(name) L"\\Driver\\"#name

#define IOCTL_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0001, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

struct MessageData {
    const char* message;
};

namespace aresdriver
{
    constexpr auto device_name = DEVICE_NAME(DxgDrv);
    constexpr auto dos_device_name = DOSDEVICE_NAME(DxgDrv);
}

extern "C" NTSTATUS CreateSpoofedDevice(_In_ struct _DRIVER_OBJECT* driver, _Out_ PDEVICE_OBJECT * device);
extern "C" VOID DestroyDevice(PDEVICE_OBJECT * device);
extern "C" NTSTATUS DeleteSymLink();
extern "C" NTSTATUS CreateSymLink(PDEVICE_OBJECT device);