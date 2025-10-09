#include <Windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    // 设置bin文件路径
    const char* binFilePath = "shellcode.bin";

    // 如果命令行提供了文件路径，使用命令行参数
    if (argc > 1) {
        binFilePath = argv[1];
    }

    printf("[+] 正在读取文件: %s\n", binFilePath);

    // 打开bin文件
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
        printf("[-] 无法打开文件，错误代码: %d\n", GetLastError());
        return -1;
    }

    // 获取文件大小
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] 无法获取文件大小\n");
        CloseHandle(hFile);
        return -1;
    }

    printf("[+] 文件大小: %d 字节\n", fileSize);

    // 分配可执行内存
    LPVOID execMemory = VirtualAlloc(
        NULL,
        fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (execMemory == NULL) {
        printf("[-] 内存分配失败\n");
        CloseHandle(hFile);
        return -1;
    }

    printf("[+] 已分配可执行内存地址: 0x%p\n", execMemory);

    // 读取文件内容到内存
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, execMemory, fileSize, &bytesRead, NULL)) {
        printf("[-] 读取文件失败\n");
        VirtualFree(execMemory, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);
    printf("[+] 成功读取 %d 字节\n", bytesRead);

    // 执行shellcode
    printf("[+] 正在执行shellcode...\n");
    ((void(*)())execMemory)();

    // 释放内存
    printf("[+] 执行完成，释放内存\n");
    VirtualFree(execMemory, 0, MEM_RELEASE);

    return 0;
}

