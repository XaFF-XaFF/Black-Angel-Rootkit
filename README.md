# Black Angel Rootkit
#### Black Angel is a Windows 11/10 x64 kernel mode rootkit. Rootkit can be loaded with enabled DSE while maintaining its full functionality. 

## Rootkit Features
Rootkit can be loaded with Black Angel Loader which is modified [kdmapper](https://github.com/TheCruZ/kdmapper) bypassing DSE. Project [driver-hijack](https://github.com/not-wlan/driver-hijack) is used to maintain full driver functionality such as IOCTL calls.
- Hide process
- Hide port
- Process elevation
- Process protection
- Shellcode injector (Unkillable shellcode. Even if process dies, shellcode can still run)
- DSE Bypass
- KPP Bypass (Unstable)

## Angel Support

- ZwProtectVirtualMemory
- MmCopyVirtualMemory
- ZwQueryInformationProcess
- ZwUnmapViewOfSection

## Resources:
- [kdmapper](https://github.com/TheCruZ/kdmapper)
- [driver-hijack](https://github.com/not-wlan/driver-hijack)
- [Cronos-Rootkit](https://github.com/XaFF-XaFF/Cronos-Rootkit)
