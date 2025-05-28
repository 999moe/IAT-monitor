# IAT-monitor
C++ x64 console tool for monitoring statically imported DLL functions using IAT hooks

## Features

- Enumerates running processes with visible windows and prompts the user to select one to monitor
- Parses the target process's PE headers to locate imported DLLs and their functions
- Hooks each imported function by injecting shellcode containing a unique counter and increment routine for every function.
- Patches the IAT entries to redirect calls from the original functions to the injected shellcode
- Monitors and displays the number of times each hooked function is called

## Usage

1. Run the program
2. Select the process you want to monitor
3. Choose the DLL whose imported functions you want to hook
4. Watch function call counts as the process runs
