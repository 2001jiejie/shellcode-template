#pragma once
#include <Windows.h>

PVOID myGetProcAddress(IN HMODULE hModule, DWORD64 dwApiNameHash);

DWORD64 djb2(char* str)
{
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
}PEB, * PPEB;

struct _UNICODE_STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    WCHAR* Buffer;                                                          //0x8
};

typedef struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef HMODULE
(WINAPI
    * myLoadLibraryA)(
        _In_ LPCSTR lpLibFileName
        );

typedef HANDLE
(WINAPI
    * myCreateFileA)(
        _In_ LPCSTR lpFileName,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_ DWORD dwCreationDisposition,
        _In_ DWORD dwFlagsAndAttributes,
        _In_opt_ HANDLE hTemplateFile
        );

typedef DWORD
(WINAPI
    * myGetFileSize)(
        _In_ HANDLE hFile,
        _Out_opt_ LPDWORD lpFileSizeHigh
        );

typedef BOOL
(WINAPI
    * myReadFile)(
        _In_ HANDLE hFile,
        _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
        _In_ DWORD nNumberOfBytesToRead,
        _Out_opt_ LPDWORD lpNumberOfBytesRead,
        _Inout_opt_ LPOVERLAPPED lpOverlapped
        );

typedef BOOL
(WINAPI
    * myCloseHandle)(
        _In_ _Post_ptr_invalid_ HANDLE hObject
        );

typedef LPVOID
(WINAPI
    * myVirtualAlloc)(
        _In_opt_ LPVOID lpAddress,
        _In_     SIZE_T dwSize,
        _In_     DWORD flAllocationType,
        _In_     DWORD flProtect
        );

typedef BOOL
(WINAPI
    * myVirtualFree)(
        _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
        _In_ SIZE_T dwSize,
        _In_ DWORD dwFreeType
        );

typedef int
(WINAPI
    * myMessageBoxA)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType);


typedef int
(WINAPI
    * myMessageBoxA)(
        _In_opt_ HWND hWnd,
        _In_opt_ LPCSTR lpText,
        _In_opt_ LPCSTR lpCaption,
        _In_ UINT uType);