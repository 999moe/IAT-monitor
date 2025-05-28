#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include <iostream>

struct ProcessStruct {
    std::string windowTitle;
    DWORD pid;
};

struct ImportedFunction
{
    std::string name;
    uintptr_t counter_address; // address of injected counter
    uintptr_t address; // actual address of imported function
};

struct ImportedDll
{
    std::string name;
    std::vector<ImportedFunction> funcs;
};

extern HANDLE hProcess; // target process
extern std::vector<ProcessStruct> processes; // vector of all visible processes

// syscall read/write process memory because why not? :P
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PSIZE_T  NumberOfBytesReaded
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PSIZE_T  NumberOfBytesWritten
    );

template<typename T>
bool WPM(uintptr_t address, const T& value)
{
    SIZE_T bytesWritten = 0;

    static pNtWriteVirtualMemory NtWrite = (pNtWriteVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");

    if (!NtWrite) return false;

    NTSTATUS status = NtWrite(
        hProcess,
        reinterpret_cast<PVOID>(address),
        const_cast<T*>(&value),
        sizeof(T),
        &bytesWritten
    );

    return (status == 0);
}

template<typename T>
T RPM(uintptr_t address)
{
    T value{};
    SIZE_T  bytesRead = 0;

    static pNtReadVirtualMemory NtRead = (pNtReadVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");

    if (!NtRead) return value;

    NTSTATUS status = NtRead(
        hProcess,
        reinterpret_cast<PVOID>(address),
        &value,
        sizeof(T),
        &bytesRead
    );

    return (status == 0) ? value : T{};
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam); // EnumWindows callback to only collect visible windows
bool RPM_bytes(uintptr_t address, BYTE* buffer, SIZE_T size); // reads bytes, same logic as templated RPM 
bool WPM_bytes(uintptr_t address, const BYTE* buffer, SIZE_T size); // writes bytes, same logic as templated WPM 
std::string readString(uintptr_t first_char); // reads a null-terminated string from remote memory
uintptr_t GetBaseAddress(DWORD pid); // gets the base address of the target .exe module


