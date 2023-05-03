#include <Windows.h>
#include <stdio.h>
#include <processthreadsapi.h>

/*
    A simple program demonstrating the 3 windows APIs ive learned so far. 
*/
int main(void){

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t buffer[100];

    // API To create a new process. Returns true on success and false in all other cases
    boolean success = CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    // Check if process creation failed
    if (!success){
        swprintf(buffer, 100, L"Failed to create process, error: %ld", GetLastError());

        // handle failure with a messagebox
        MessageBoxW(
            NULL,
            buffer,
            L"Critical Failure",
            MB_OK | MB_ICONERROR
        );

        return EXIT_FAILURE;
    }

    printf("\n(+) Process Created");
    printf("\n(+) Process PID: %ld", pi.dwProcessId);
    printf("\n(+) Opening Process");

    // Attempt to get a handle to the created process. OpenProcess will return the handle if successful
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        pi.dwProcessId
    );

    // If the handle is null, open process failed
    if (hProcess == NULL){
        swprintf(buffer, 100, L"Failed to open process, error: %ld", GetLastError());

        // close open handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        MessageBoxW(
            NULL,
            buffer,
            L"Critical Failure",
            MB_OK | MB_ICONERROR
        );

        return EXIT_FAILURE;
    }

    printf("\n(+) Process Opened");
    printf("\n(+) Process Handle: %p", hProcess);

    // cleanup
    printf(("\n\n(+) Closing handles..."));
    CloseHandle(hProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return EXIT_SUCCESS;
}