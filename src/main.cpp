#include "utils.h"

HANDLE hProcess;
std::vector<ProcessStruct> processes;
std::vector<ImportedDll> importedDlls;

int main()
{
    EnumWindows(EnumWindowsProc,0);

    // list processes with visible windows
    std::cout << "Enter process index to monitor: \n";
    std::cout << "-----------------------------------\n\n";
    for (int i = 0; i < processes.size(); i++)
    {
        std::cout << (i + 1) << "- " << processes[i].windowTitle << std::endl;
    }
    std::cout << "\nEnter your choice: ";
    int choice = 0;
    std::cin >> choice;

    ProcessStruct target = processes[choice - 1];
    uintptr_t target_base = GetBaseAddress(target.pid);
    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, target.pid);
    if (hProcess == nullptr) {
        std::cerr << "Failed to open target process.\n";
        return 1;
    }

    // start with dos header to get to the import table
    _IMAGE_DOS_HEADER dos_header = RPM<_IMAGE_DOS_HEADER>(target_base);
    uintptr_t nt_header_offset = dos_header.e_lfanew;
    _IMAGE_NT_HEADERS64  nt_headers = RPM<_IMAGE_NT_HEADERS64>(target_base + nt_header_offset);
    _IMAGE_DATA_DIRECTORY import_dir = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    DWORD import_descriptor_rva = import_dir.VirtualAddress;

    // loop imported dlls until Name == 0 -> end
    int dll_index = 0;
    while (true)
    {
        IMAGE_IMPORT_DESCRIPTOR current_descriptor = RPM<IMAGE_IMPORT_DESCRIPTOR>(target_base + import_descriptor_rva + sizeof(IMAGE_IMPORT_DESCRIPTOR) * dll_index);
        if (current_descriptor.Name == 0)
            break;
        else
        {
            std::string result = readString((target_base + current_descriptor.Name));
          
            int index = 0;
            ImportedDll curDll;
            curDll.name = result;

            // loop dll functions until Import Name Table entry value is 0
            int funcCount = 0;
            while (true)
            {
                ImportedFunction curFunc;

                uintptr_t INA_ENTRY = target_base + current_descriptor.OriginalFirstThunk + index * sizeof(uintptr_t);
                uintptr_t INA_ENTRY_VALUE = target_base +RPM<uintptr_t>(INA_ENTRY);
                if (RPM<uintptr_t>(INA_ENTRY) == 0)
                    break;

                std::string func_name = readString(INA_ENTRY_VALUE +sizeof(WORD));
                if (!func_name.empty()) 
                {
                    funcCount++;
                    curFunc.name = func_name;
                    uintptr_t iatEntryAddr = target_base + current_descriptor.FirstThunk + index * sizeof(uintptr_t);
                    uintptr_t IAT_ENTRY = RPM<uintptr_t>(iatEntryAddr); 
                    curFunc.address = IAT_ENTRY;
                    if (IAT_ENTRY == 0) 
                    {
                        index++;
                        continue;
                    }

                    // check if writing to entry's address is possible, skip if not to avoid crash
                    MEMORY_BASIC_INFORMATION mbi;
                    if (!VirtualQueryEx(hProcess, (LPCVOID)IAT_ENTRY, &mbi, sizeof(mbi)) ||
                        !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) ||
                        mbi.State != MEM_COMMIT ||
                        (mbi.Protect & PAGE_GUARD))
                    {
                        index++;
                        continue;
                    }

                    // allocate memory for counter and counter increment function in process
                    LPVOID counter_func = VirtualAllocEx(hProcess, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    LPVOID counter_int = VirtualAllocEx(hProcess, nullptr, sizeof(int), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                    // prep increment shellcode, fill in counter and original function addresses, inject, and patch IAT entry (profit)
                    BYTE shellcode[24] = {
                        0x48, 0xB8,              
                        0,0,0,0,0,0,0,0,         
                        0xFF, 0x00,              
                        0x48, 0xB8,              
                        0,0,0,0,0,0,0,0,         
                        0xFF, 0xE0               
                    };

                    uint64_t counterAddr = (uint64_t)counter_int;
                    memcpy(shellcode + 2, &counterAddr, sizeof(counterAddr));

                    uint64_t originalFuncAddr = (uint64_t)curFunc.address;
                    memcpy(shellcode + 14, &originalFuncAddr, sizeof(originalFuncAddr));

                    WPM_bytes((uintptr_t)counter_func, shellcode, sizeof(shellcode));
                    WPM<int>((uintptr_t)counter_int, 0);

                    // change IAT entry's protection to allow writing
                    DWORD oldProtect;
                    VirtualProtectEx(hProcess, (LPVOID)iatEntryAddr, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);

                    WPM<LPVOID>(iatEntryAddr, counter_func);

                    DWORD tmp;
                    VirtualProtectEx(hProcess, (LPVOID)iatEntryAddr, sizeof(uintptr_t), oldProtect, &tmp);

                    curFunc.counter_address = (uintptr_t)counter_int;
                    curDll.funcs.push_back(curFunc);

                }
                index++;
               
            }
            if (!curDll.funcs.empty())
                importedDlls.push_back(curDll);
            dll_index++;
        }

    }
    
    system("cls");

    std::cout << "Available DLLs to monitor (" << importedDlls.size() << "):\n\n";

    for (int i = 0; i < importedDlls.size(); ++i)
    {
        const ImportedDll& curDll = importedDlls[i];
        std::string indexStr = "<" + std::to_string(i + 1) + ">";
        std::string header = indexStr + " " + curDll.name;

        std::cout << "\n" << header << "\n";
        std::cout << std::string(header.length(), '-') << "\n";
        for (const ImportedFunction& curFunc : curDll.funcs)
        {
            std::cout << "  - " << curFunc.name << "\n";
        }
        std::cout << "\n";
    }

    int selectedDllIndex;
    std::cout << "\n\n>Enter dll index to monitor: ";
    std::cin >> selectedDllIndex;

    if (selectedDllIndex < 1 || selectedDllIndex > importedDlls.size()) 
    {
        std::cerr << "Invalid DLL index. Exiting...\n";
        return 1;
    }

    system("cls");
    std::cout << "Watching DLL: " << importedDlls[selectedDllIndex - 1].name << "\n\n";

    // only print functions called at least once since last update
    std::map<uintptr_t, int> lastCounts;
    while (true)
    {
        bool once = false;
        const ImportedDll& curDll = importedDlls[selectedDllIndex - 1];
        for (const ImportedFunction& curFunc : curDll.funcs)
        {
            int current = RPM<int>(curFunc.counter_address);
            int& last = lastCounts[curFunc.counter_address];

            if (current != last)
            {
                std::cout << curFunc.name
                    << " - was called -> total count: "
                    << current << "\n";

                last = current;
                once = true;
            }
        }
        if (once)
            std::cout << "---------" <<std::endl;
        Sleep(1000);
    }

}