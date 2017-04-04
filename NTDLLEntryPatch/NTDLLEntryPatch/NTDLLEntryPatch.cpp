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
#include "NTDLLEntryPatch.h"

/*
TODO:
Refactorize
check memory operations & paths bounds etc
fix possibles buffers overflows, underruns etc.
Documentation
Consistent Variable Names
....
*/

int main(int argc, char* argv[])
{
    int retf = NTDLLEntryPatch(argc, argv);

    puts("Press enter to exit.");
    getchar();
    
    return retf;
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

    EnableDebugPrivilege();

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

void BadSyntax(void)
{
    fprintf(stderr, "Error syntax, use: command.exe PID p/u\n"
        "   'p' for patch\n"
        "   'u' for unpatch\n");
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
        unsigned char code_before_patch[0x40] = { 0 };
        unsigned char code_after_patch[0x40] = { 0 };
        DWORD total_bytes = 0;

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
            printf("Unpatching with: 0x%02X 0x%02X \n", jmp_itfself[0], jmp_itfself[1]);
        }
        else
        {
            printf("Patching with JMP itself: 0x%02X 0x%02X \n", jmp_itfself[0], jmp_itfself[1]);
        }

        PatchCode(
            hProcess, 
            ntdll_ep, 
            jmp_itfself, 
            sizeof(jmp_itfself),
            code_before_patch,
            sizeof(code_before_patch),
            code_after_patch,
            sizeof(code_after_patch)
        );

        puts("Remote instructions before the patch:");
        total_bytes = GetBytesInstructionsReplaced(code_before_patch, ntdll_ep, sizeof(jmp_itfself), sizeof(code_before_patch));
        if (patch)
        {
            CheckDangerousInstructions(code_before_patch, ntdll_ep, total_bytes);
        }

        puts("Remote instructions after the patch:");
        total_bytes = GetBytesInstructionsReplaced(code_after_patch, ntdll_ep, sizeof(jmp_itfself), sizeof(code_after_patch));
        if (!patch)
        {
            CheckDangerousInstructions(code_after_patch, ntdll_ep, total_bytes);
        }

        CloseHandle(hProcess);
    }
    else
    {
        fprintf(stderr, "Error openning process\n");
    }

    return true;
}