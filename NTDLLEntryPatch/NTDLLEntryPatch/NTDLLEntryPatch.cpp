/*
DbgChild - NTDLL Entry Patch
-
MIT License
-
Copyright (c) <2017> <David Reguera Garcia aka Dreg>
http://www.fr33project.org/
https://github.com/David-Reguera-Garcia-Dreg
dreg@fr33project.org
-
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "stdafx.h"
#include <windows.h>
#include <inttypes.h>

/*
TODO:
Refactorize
check memory operations & paths bounds etc
fix possibles buffers overflows, underruns etc.
Documentation
Consistent Variable Names
....
*/

#define PAGE_SIZE 4096
#define PAGE_ROUND_DOWN(x) (((ULONG_PTR)(x)) & (~(PAGE_SIZE-1)))

typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

typedef void (WINAPI* GetNativeSystemInfo_t)(
    _Out_ LPSYSTEM_INFO lpSystemInfo
    );

LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)
GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");


GetNativeSystemInfo_t GetNativeSystemInfo_f = (GetNativeSystemInfo_t)GetProcAddress(
    GetModuleHandleW(L"kernel32"), "GetNativeSystemInfo");

BOOL Is64BitProcess(HANDLE process)
{
    BOOL isWow64 = FALSE;
    SYSTEM_INFO si = { 0 };

    if (GetNativeSystemInfo_f == NULL || fnIsWow64Process == NULL)
    {
        return FALSE;
    }

    GetNativeSystemInfo_f(&si);
    if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
    {
        return FALSE;
    }

    fnIsWow64Process(process, &isWow64);

    return isWow64 ? FALSE : TRUE;
}

bool PatchUnpatchNTDLL(DWORD pid, bool patch)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    void* ntdll_ep = GetProcAddress(GetModuleHandleW(L"ntdll"), "LdrInitializeThunk");

    if (patch)
    {
        puts("PATCH MODE");
    }
    else
    {
        puts("UNPATCH MODE");
    }

    printf("NTDLL EP LdrInitializeThunk: 0x%" PRIXPTR "\n", (uintptr_t)ntdll_ep);
    printf("PID: %" PRIu64 " , Handle: %" PRIu64 "\n", (uint64_t)pid, (uint64_t)hProcess);

    if (hProcess)
    {
        unsigned char jmp_itfself[] = { 0xEB, 0xFE };
        SIZE_T bytes_written = 0;
        DWORD old_protect = 0;
        DWORD now_protect = 0;
        BOOL is_64_proc = Is64BitProcess(hProcess);

        puts(
            "Process Openned!\n"
            "Assuming the local NTDLL its unpatched"
        );

        printf("Remote process is: ");
        if (is_64_proc)
        {
            puts("x64");
        }
        else
        {
            puts("x32");
        }

        if (is_64_proc != Is64BitProcess(GetCurrentProcess()))
        {
            fprintf(stderr, "Error, you must use:\n"
                "NTDLLEntryPatch_x32 for x32 processes.\n"
                "NTDLLEntryPatch_x64 for x64 processes.\n"
            );
            CloseHandle(hProcess);
            return FALSE;
        }


        if (!patch)
        {
            jmp_itfself[0] = ((unsigned char*)ntdll_ep)[0];
            jmp_itfself[1] = ((unsigned char*)ntdll_ep)[1];
        }
        else
        {
            puts("(JMP itself)");
        }

        puts("Data to write in the remote process: ");
        for (int i = 0; i < sizeof(jmp_itfself); i++)
        {
            printf("0x%02X ", jmp_itfself[i]);
        }
        putchar('\n');

        VirtualProtectEx(hProcess, (LPVOID)PAGE_ROUND_DOWN(ntdll_ep), PAGE_SIZE,
            PAGE_EXECUTE_READWRITE,
            &old_protect);

        printf("changed remote page rights 0x%" PRIXPTR " to PAGE_EXECUTE_READWRITE\n", (uintptr_t)PAGE_ROUND_DOWN(ntdll_ep));

        WriteProcessMemory(hProcess, ntdll_ep, jmp_itfself, sizeof(jmp_itfself),
            &bytes_written);

        printf("patched 0x%" PRIXPTR " , bytes written: %d\n", (uintptr_t)ntdll_ep, (int)bytes_written);

        VirtualProtectEx(hProcess, (LPVOID)PAGE_ROUND_DOWN(ntdll_ep), PAGE_SIZE,
            old_protect,
            &now_protect);

        printf("restored page rights 0x%" PRIXPTR " to %d\n", (uintptr_t)PAGE_ROUND_DOWN(ntdll_ep), now_protect);

        CloseHandle(hProcess);
    }
    else
    {
        fprintf(stderr, "Error openning process\n");
    }

    return true;
}

void BadSyntax(void)
{
    fprintf(stderr, "Error syntax, use: command.exe PID p/u\n"
        "   'p' for patch\n"
        "   'u' for unpatch\n");
}

int NTDLLEntryPatch(int argc, char** argv)
{
    DWORD pid = 0;
    bool patch = false;

    printf("\n"
        "DbgChild - NTDLL Entry Patch\n"
        "-\n"
        "MIT License\n"
        "-\n"
        "Copyright (c) <2017> <David Reguera Garcia aka Dreg>\n"
        "http://www.fr33project.org/\n"
        "https://github.com/David-Reguera-Garcia-Dreg\n"
        "dreg@fr33project.org\n"
        "- \n"
        "NTDLL Entry Patch Version: "
    );

#ifdef _WIN64
    puts("x64");
#else
    puts("x86");
#endif

    puts("-\n");

    if (argc < 3)
    {
        BadSyntax();
        return -1;
    }

    if (tolower(argv[2][0]) == 'p')
    {
        patch = true;
    }
    else if (tolower(argv[2][0]) == 'u')
    {
        patch = false;
    }
    else
    {
        BadSyntax();
        return -1;
    }

    pid = atoi(argv[1]);

    PatchUnpatchNTDLL(pid, patch);

    return 0;
}

int main(int argc, char* argv[])
{
    int retf = NTDLLEntryPatch(argc, argv);

    puts("Press enter to exit.");
    getchar();
    
    return retf;
}

