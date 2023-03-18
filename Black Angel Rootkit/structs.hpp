#pragma once
#include <fltKernel.h>
#include <ntddk.h>
#include <ntimage.h>
#include "debug.hpp"

// disable warning for unnamed structs/unions because i cant be arsed to name undocumented win structs lol
#pragma warning(disable: 4201)
typedef struct _OBJECT_CREATE_INFORMATION
{
    ULONG Attributes;
    PVOID RootDirectory;
    PVOID ParseContext;
    CHAR ProbeMode;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    ULONG SecurityDescriptorCharge;
    PVOID SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, * POBJECT_CREATE_INFORMATION;

// This structure is not correct on Windows 7, but the offsets we need are still correct.
// Prepended to every OBJECT at a negative offset
typedef struct _OBJECT_HEADER
{
    LONG PointerCount;
    union
    {
        LONG HandleCount;
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;
    union
    {
        UCHAR TraceFlags;
        struct
        {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
            UCHAR Reserved : 6;
        };
    };
    UCHAR InfoMask;
    union
    {
        UCHAR Flags;
        struct
        {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };
    union
    {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;

// if MaintainTypeList is 1 TypeList contains the entries. Sadly it's not maintained for IoDriverObjectType
typedef struct _OBJECT_TYPE_INITIALIZER
{
    USHORT Length;
    UCHAR ObjectTypeFlags;
    ULONG CaseInsensitive : 1;
    ULONG UnnamedObjectsOnly : 1;
    ULONG UseDefaultObject : 1;
    ULONG SecurityRequired : 1;
    ULONG MaintainHandleCount : 1;
    ULONG MaintainTypeList : 1;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    LONG* OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    LONG* ParseProcedure;
    LONG* SecurityProcedure;
    LONG* QueryNameProcedure;
    UCHAR* OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

// OBJECT_TYPE is an OBJECT of Type TypeObject
typedef struct _OBJECT_TYPE
{
    // ERESOURCE Mutex; -> not in WinDbg probably negative offset or removed
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    UCHAR Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
    EX_PUSH_LOCK TypeLock;
    ULONG Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _DEVICE_MAP* PDEVICE_MAP;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
    _OBJECT_DIRECTORY_ENTRY* ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
    POBJECT_DIRECTORY_ENTRY HashBuckets[37];
    EX_PUSH_LOCK Lock;
    PDEVICE_MAP DeviceMap;
    ULONG SessionId;
    PVOID NamespaceEntry;
    ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    // ULONG padding on IA64
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    // ULONG padding on IA64
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


EXTERN_C NTSYSCALLAPI NTSTATUS ZwOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
EXTERN_C NTSYSCALLAPI VOID ExAcquirePushLockExclusiveEx(PEX_PUSH_LOCK, ULONG Flags);
EXTERN_C NTSYSCALLAPI VOID ExReleasePushLockExclusiveEx(PEX_PUSH_LOCK, ULONG Flags);
EXTERN_C NTSYSCALLAPI PLIST_ENTRY PsLoadedModuleList;
EXTERN_C NTSYSCALLAPI PVOID RtlImageDirectoryEntryToData(_In_  PVOID   Base, _In_  BOOLEAN MappedAsImage, _In_  USHORT  DirectoryEntry, _Out_ PULONG  Size);
EXTERN_C NTSYSCALLAPI PVOID ObQueryNameInfo(_In_ PVOID Object);
// empty icall dispatch handler to disable cfg
extern "C" void _ignore_icall(void);