#include "utils.h"

bool WPM_bytes(uintptr_t address, const BYTE* buffer, SIZE_T size)
{
    SIZE_T bytesWritten = 0;

    static auto NtWrite = (pNtWriteVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");

    if (!NtWrite) return false;

    NTSTATUS status = NtWrite(
        hProcess,
        reinterpret_cast<PVOID>(address),
        const_cast<BYTE*>(buffer),
        size,
        &bytesWritten
    );

    return (status == 0) && (bytesWritten == size);
}

bool RPM_bytes(uintptr_t address, BYTE* buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;

    static auto NtRead = (pNtReadVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

    if (!NtRead) return false;

    NTSTATUS status = NtRead(
        hProcess,
        reinterpret_cast<PVOID>(address),
        buffer,
        size,
        &bytesRead
    );

    return (status == 0) && (bytesRead == size);
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    if (GetParent(hwnd) != nullptr)
        return TRUE;
    if (!IsWindowVisible(hwnd))
        return TRUE;
    int titleLength = GetWindowTextLength(hwnd);
    if (titleLength == 0)
        return TRUE;

    char buffer_text[256];
    GetWindowTextA(hwnd, buffer_text, 256);

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    wchar_t buffer_exe[MAX_PATH];
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    GetModuleFileNameW((HMODULE)hProc, buffer_exe, MAX_PATH);
    processes.push_back({ std::string(buffer_text),pid });
    return TRUE;
}

uintptr_t GetBaseAddress(DWORD pid) {
    uintptr_t baseAddress = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32 moduleEntry = { sizeof(MODULEENTRY32) };
    if (Module32First(snapshot, &moduleEntry)) {
        baseAddress = reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
    }

    CloseHandle(snapshot);
    return baseAddress;
}

std::string readString(uintptr_t first_char)
{
    std::string result = "";
    for (int i = 0; i < 256; i++)
    {
        char cur_char = RPM<char>(first_char + i);
        if (cur_char == '\0')
            break;
        result += cur_char;
    }
    return result;
}