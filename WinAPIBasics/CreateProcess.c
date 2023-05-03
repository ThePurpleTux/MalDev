#include <Windows.h>
#include <stdio.h>

int main(void){

    /*
    BOOL CreateProcessW(
        [in, optional]      LPCWSTR               lpApplicationName, 
        [in, out, optional] LPWSTR                lpCommandLine,
        [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
        [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
        [in]                BOOL                  bInheritHandles,
        [in]                DWORD                 dwCreationFlags,
        [in, optional]      LPVOID                lpEnvironment,
        [in, optional]      LPCWSTR               lpCurrentDirectory,
        [in]                LPSTARTUPINFOW        lpStartupInfo,
        [out]               LPPROCESS_INFORMATION lpProcessInformation
    );

    This API returns a boolean. It returns true if the process is created and false in any other case. We can use this to do different things depending of if the process is created or not. 
    In the example below, we chack the return value, and if it is false, we return an exit failure

    Most of the params are optional. Applicartion name and command line are self explanatory
    Process attribs and Thread Attribs reffer to security attribs and for our cases we can make them null
    bInheritHandles tells the API if we want to inherrit handles. We choose no
    CreationFlags is where we can set the priority of our new process
    Environment is a pointer to the Env block for the new process to use. If set to null, it will use the env of the calling process
    Current Dir is self explanatory. If null it will use the same dir as the calling process.
    Startup information and Process information are references to two already existing structs. These need to be assigned to a variable somewhere in our code before being passed in here. Note we need ot use the W versions since we are using create process W
    */

    STARTUPINFOW si = { 0 }; // Creating the startupinfo var
    PROCESS_INFORMATION pi = { 0 }; // Creating the PROCESS INFO var

    boolean success = CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        BELOW_NORMAL_PRIORITY_CLASS,
        NULL,
        NULL,
        &si, // to reference a struct, we use the & symbol
        &pi
    );

    if (!success){
        printf("(-) Failed to create process, error: %ld", GetLastError());
        return EXIT_FAILURE;
    }

    /*
        Once we have a process, we can start to retrieve information from it. SInce the process info var is outpu tby the API we can pull this info from that Struct
    */
   printf("\n(+) Process started! PID: %ld", pi.dwProcessId);
   printf("\n(+) Process Thread started! TID: %ld", pi.dwThreadId);

    return EXIT_SUCCESS;
}