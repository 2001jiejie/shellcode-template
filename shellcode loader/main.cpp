#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    // ����bin�ļ�·��
    const char* binFilePath = "shellcode.bin";

    // ����������ṩ���ļ�·����ʹ�������в���
    if (argc > 1) {
        binFilePath = argv[1];
    }

    printf("[+] ���ڶ�ȡ�ļ�: %s\n", binFilePath);

    // ��bin�ļ�
    HANDLE hFile = CreateFileA(
        binFilePath,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] �޷����ļ����������: %d\n", GetLastError());
        return -1;
    }

    // ��ȡ�ļ���С
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] �޷���ȡ�ļ���С\n");
        CloseHandle(hFile);
        return -1;
    }

    printf("[+] �ļ���С: %d �ֽ�\n", fileSize);

    // �����ִ���ڴ�
    LPVOID execMemory = VirtualAlloc(
        NULL,
        fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (execMemory == NULL) {
        printf("[-] �ڴ����ʧ��\n");
        CloseHandle(hFile);
        return -1;
    }

    printf("[+] �ѷ����ִ���ڴ��ַ: 0x%p\n", execMemory);

    // ��ȡ�ļ����ݵ��ڴ�
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, execMemory, fileSize, &bytesRead, NULL)) {
        printf("[-] ��ȡ�ļ�ʧ��\n");
        VirtualFree(execMemory, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);
    printf("[+] �ɹ���ȡ %d �ֽ�\n", bytesRead);

    // ִ��shellcode
    printf("[+] ����ִ��shellcode...\n");
    ((void(*)())execMemory)();

    // �ͷ��ڴ�
    printf("[+] ִ����ɣ��ͷ��ڴ�\n");
    VirtualFree(execMemory, 0, MEM_RELEASE);

    return 0;
}

