#pragma once
#include <ntddk.h>
#include "debug.hpp"

extern "C" NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT* DriverObject, PUNICODE_STRING RegistryPath);
extern "C" __declspec(dllexport) VOID DriverUnload(_In_ struct _DRIVER_OBJECT*);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)