#pragma once
#include "structs.hpp"
#include "util.hpp"
#include "debug.hpp"

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) extern "C" NTSTATUS CatchDeviceCtrl(PDEVICE_OBJECT, PIRP);
_Dispatch_type_(IRP_MJ_CREATE) extern "C" NTSTATUS CatchCreate(PDEVICE_OBJECT, PIRP);
_Dispatch_type_(IRP_MJ_CLOSE) extern "C"  NTSTATUS CatchClose(PDEVICE_OBJECT, PIRP);
extern "C" VOID UnloadDriver(PDRIVER_OBJECT);
extern "C" NTSTATUS CallOriginal(int idx, _In_ struct _DEVICE_OBJECT* DeviceObject, _Inout_ struct _IRP* Irp);
extern "C" VOID DispatchUnload(PDRIVER_OBJECT);

#pragma alloc_text(NONPAGED, CatchDeviceCtrl)
#pragma alloc_text(NONPAGED, CatchCreate)
#pragma alloc_text(NONPAGED, CatchClose)
#pragma alloc_text(NONPAGED, UnloadDriver)
#pragma alloc_text(NONPAGED, CallOriginal)
#pragma alloc_text(NONPAGED, DispatchUnload)

extern "C" NTSTATUS HijackDriver(_In_ struct _DRIVER_OBJECT* driver);
extern "C" NTSTATUS FindDriver(_In_ struct _DRIVER_OBJECT* ignore = nullptr);
extern "C" VOID RestoreDriver();

#pragma alloc_text(INIT, HijackDriver)
#pragma alloc_text(INIT, FindDriver)
#pragma alloc_text(NONPAGED, RestoreDriver)


template<typename... Args>
bool all_hookable(PDRIVER_OBJECT driver, Args... args) { return (... && IsHookableIRPHandler(driver, args)); }