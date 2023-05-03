// Includes are the equivlent of imports in other languages. Includes allow you to tell your program which header files to user
// Header files contain type defenitiions, structs, other includes, etc... 

#include <Windows.h> // The header that allows us to interact with Win32 APIs 

int main(void) {

    // Syntax from msdn: int MessageBox([in, optional] HWND    hWnd, [in, optional] LPCTSTR lpText, [in, optional] LPCTSTR lpCaption, [in]           UINT    uType);

    // Most windows APIs have several different versions. The W version of an API stands for Wide Char, which means Unicode. The A version stands for ANSI

    // First param is a handle to the owner window. We do not need to have an owner window and so we leave it as null
    // The second param is the text we want to display. 
    // Third param is the messagebox title
    // The fourth param is a set of options that define the behavior of the box. ie, what buttons there are, the icon, will it prevent the user from doing anything else?
    int boxResult = MessageBoxW(
        NULL, 
        L"This is my first message box in C",  // Since we are using the W version of message box, all our strings need to be unicode encoded. We do this by adding an L in front of the string. Alternatively, we could use the ANSI version of message box if we dont want to use unicode
        L"MessageBox Test", 
        MB_YESNOCANCEL | MB_ICONQUESTION | MB_TASKMODAL
    );
    // MessageBox also returns an int whos value will be determined by what the user does. This can be used for control from:
    
    /*
    There are also various versions of APIs labled with Ex. Ex stands for extended and these APIs usually allow you to do more things with them
    One example is CreateRemoteThread, and CreateRemoteThreadEx. 
    */
    return EXIT_SUCCESS;


    // With a basic understanding of how Win32 APIs work, we can move on to playing with an API we will use a lot, CreateProcess
}