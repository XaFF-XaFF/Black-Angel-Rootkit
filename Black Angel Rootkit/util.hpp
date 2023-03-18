#pragma once
#include "structs.hpp"
#include "debug.hpp"

extern "C" NTSTATUS GetNtoskrnl(OUT PKLDR_DATA_TABLE_ENTRY * out_entry);
extern "C" bool IsInNtoskrnl(PVOID address);
extern "C" bool IsHookableIRPHandler(PDRIVER_OBJECT driver, PDRIVER_DISPATCH dispatch);
extern "C" NTSTATUS GetModule(IN PUNICODE_STRING name, OUT PKLDR_DATA_TABLE_ENTRY * out_entry);

#pragma alloc_text(INIT, GetNtoskrnl)
#pragma alloc_text(INIT, IsInNtoskrnl)
#pragma alloc_text(INIT, IsHookableIRPHandler)
#pragma alloc_text(INIT, GetModule)

extern "C" NTSTATUS CopyMajorFunctions(_In_reads_bytes_(count * sizeof(PDRIVER_DISPATCH)) PDRIVER_DISPATCH * src, _Out_writes_bytes_all_(count * sizeof(PDRIVER_DISPATCH)) PDRIVER_DISPATCH * dst, SIZE_T size);
extern "C" ULONGLONG SetCfgDispatch(PDRIVER_OBJECT driver, ULONGLONG new_dispatch);

#pragma alloc_text(NONPAGED, CopyMajorFunctions)
#pragma alloc_text(NONPAGED, SetCfgDispatch)