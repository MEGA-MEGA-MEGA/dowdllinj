#include <iostream>
#include <string>
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );
// Поиск pid 
DWORD GetProcId(const wchar_t name[]) {
    DWORD pid = 0;
    HWND hWnd = FindWindow(NULL, name);
    if (hWnd == nullptr) {
        return pid;
    }
    GetWindowThreadProcessId(hWnd, &pid);
    return pid;
}
// Создание потока для подгрузки нашей dll
bool InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    PVOID remoteMemory = NULL;
    remoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory) {
        std::cout << "Не удалось выделить память\n";
        CloseHandle(hProcess);
        return false;
    }
    WriteProcessMemory(hProcess, remoteMemory, dllPath, strlen(dllPath) + 1, NULL);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!NtCreateThreadEx) {
        std::cout << "Не удалось получить NtCreateThreadEx\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        0x1FFFFF,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        remoteMemory,
        FALSE,
        0,
        0,
        0,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        std::cout << "Не удалось создать поток\n";
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;

}

int main()
{
    setlocale(LC_ALL, "");
    std::string dllPath;
    std::cout << "Введите полный путь к DLL: ";
    std::getline(std::cin, dllPath);
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "Файл не найден: " << dllPath << std::endl;
        std::cin.get();
        return 1;
    }
    DWORD pid = 0;
    while (!pid) {
        pid = GetProcId(L"Dawn of War: Soulstorm");
        Sleep(1000);
    }
    if (InjectDLL(pid, dllPath.c_str())) {
        std::cout << "Успех!\n";
    }
    else {
        std::cout << "Что-то пошло не так...\n";
    }
    std::cin.get();
}