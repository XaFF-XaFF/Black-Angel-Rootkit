#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <minwindef.h>

#define IOCTL_NSI_GETALLPARAM 0x12001b

typedef enum _NSI_PARAM_TYPE
{
	Udp = 1,
	Tcp = 3
} NSI_PARAM_TYPE;

typedef struct _NSI_TCP_SUBENTRY
{
	BYTE Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	BYTE IpAddress6[16];
	BYTE Reserved2[4];
} NSI_TCP_SUBENTRY, * PNSI_TCP_SUBENTRY;

typedef struct _HOOKED_IO_COMPLETION {
	PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
	PVOID OriginalContext;
	LONG InvokeOnSuccess;
	PEPROCESS RequestingProcess;
} HOOKED_IO_COMPLETION, * PHOOKED_IO_COMPLETION;

typedef struct _NSI_TCP_ENTRY
{
	NSI_TCP_SUBENTRY Local;
	NSI_TCP_SUBENTRY Remote;
} NSI_TCP_ENTRY, * PNSI_TCP_ENTRY;

typedef struct _NSI_UDP_ENTRY
{
	BYTE Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	BYTE IpAddress6[16];
	BYTE Reserved2[4];
} NSI_UDP_ENTRY, * PNSI_UDP_ENTRY;

typedef struct _NSI_STATUS_ENTRY
{
	ULONG State;
	BYTE Reserved[8];
} NSI_STATUS_ENTRY, * PNSI_STATUS_ENTRY;

typedef struct _NSI_PROCESS_ENTRY
{
	ULONG UdpProcessId;
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG TcpProcessId;
	ULONG Reserved3;
	ULONG Reserved4;
	ULONG Reserved5;
	ULONG Reserved6;
} NSI_PROCESS_ENTRY, * PNSI_PROCESS_ENTRY;

typedef struct _NSI_PARAM
{
	SIZE_T Reserved1;
	SIZE_T Reserved2;
	LPVOID ModuleId;
	NSI_PARAM_TYPE Type;
	ULONG Reserved3;
	ULONG Reserved4;
	LPVOID Entries;
	SIZE_T EntrySize;
	LPVOID Reserved5;
	SIZE_T Reserved6;
	PNSI_STATUS_ENTRY StatusEntries;
	SIZE_T Reserved7;
	PNSI_PROCESS_ENTRY ProcessEntries;
	SIZE_T ProcessEntrySize;
	SIZE_T Count;
} NSI_PARAM, * PNSI_PARAM;

typedef struct _HP_CONTEXT
{
	PIO_COMPLETION_ROUTINE oldIocomplete;
	PVOID oldCtx;
	BOOLEAN bShouldInvolve;
	PKPROCESS pcb;
}HP_CONTEXT, * PHP_CONTEXT;