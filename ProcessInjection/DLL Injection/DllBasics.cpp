// DLL stands for Dynamic Link Library
// In simple terms, a DLL stores functions that other windows processes can use
// DLLs allow multiple applications to share the same code, rather than needing to write the same code over and over

/*
#include <stdio.h>
#include <windows.h>

int main(void) {

	MessageBoxW(NULL, L"MesageBox Works", L"Test", MB_ICONQUESTION);
	return EXIT_SUCCESS;

}

You should understand the above code by now. What if we wanted to do the same thing with a DLL?
*/

//Like any other program, dlls have a main function. For dlls, its called "dllmain":
/*
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
);

msdn has several examples for how to build a DLL main function
*/

// our DLL will be very simple
#include <windows.h>

// The main function takes in 3 things:
// a handle to the Dll Module (ie the base address of the dll)
// the reason for calling the entrypoint
// If fdwReason is DLL_PROCESS_ATTACH, lpvReserved is NULL for dynamic loads and non-NULL for static loads. | If fdwReason is DLL_PROCESS_DETACH, lpvReserved is NULL if FreeLibrary has been called or the DLL load failed and non-NULL if the process is terminating.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD nReason, LPVOID lpvReserved){
    switch(nReason){
        case DLL_PROCESS_ATTACH:
            MessageBoxW(NULL, L"My DLL Works", L"Working DLL", MB_OK);
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

// Just like that, we have ourselves a dll