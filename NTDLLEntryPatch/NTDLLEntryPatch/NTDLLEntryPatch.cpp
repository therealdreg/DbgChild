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

MY_OWN_LOGW_t* my_log;

int main(int argc, char* argv[])
{
    my_log = InitLog(L"NTDLLEntryPatch");

    int retf = NTDLLEntryPatch(argc, argv);

    WCHAR full_path_log[MAX_PATH] = { 0 };

    wcscpy_s(full_path_log, GetLogFullPathW(my_log));

    CloseLog(my_log);

    if (argc >= 4)
    {
        if (tolower((argv[3])[0]) == 'l')
        {
            ShellExecuteW(NULL, L"open", full_path_log, NULL, NULL, SW_SHOWNORMAL);
        }
    }

    return retf;
}

int NTDLLEntryPatch(int argc, char** argv)
{
    DWORD pid = 0;
    bool patch = false;

    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"\r\n"
        L"DbgChild - NTDLL Entry Patch\r\n"
        L"-\r\n"
        L"MIT License\r\n"
        L"-\r\n"
        L"Copyright (c) <2017> <David Reguera Garcia aka Dreg>\r\n"
        L"http://www.fr33project.org/\r\n"
        L"https://github.com/David-Reguera-Garcia-Dreg\r\n"
        L"dreg@fr33project.org\r\n"
        L"-\r\n"
        L"NTDLLEntryPatch Version: %s\r\n\r\n"
        ,
#ifdef _WIN64
        L"x64"
#else
        L"x86"
#endif
    );

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
    LogW(
        my_log,
        TRUE,
        LOG_TAG_ERROR
        L"Error syntax, use: command.exe PID p/u\r\n"
        L"   'p' for patch\r\n"
        L"   'u' for unpatch\r\n");
}

bool PatchUnpatchNTDLL(DWORD pid, bool patch)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    void* ntdll_ep = GetProcAddress(GetModuleHandleW(L"ntdll"), "LdrInitializeThunk");

    if (patch)
    {
        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"PATCH MODE\r\n");
    }
    else
    {
        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"UNPATCH MODE\r\n");
    }

    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"NTDLL EP LdrInitializeThunk: 0x%" PRIXPTR "\r\n"
        L"PID: %" PRIu64 " , Handle: %" PRIu64 "\r\n"
        ,
        (uintptr_t)ntdll_ep,
        (uint64_t)pid, 
        (uint64_t)hProcess
    );

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

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Process Openned!\r\n"
            L"Assuming the local NTDLL its unpatched\r\n"
        );

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Remote process is: %s\r\n", is_64_proc ? L"x64" : L"x32");

        if (is_64_proc != Is64BitProcess(GetCurrentProcess()))
        {
            LogW(
                my_log,
                TRUE,
                LOG_TAG_ERROR
                L"Error, you must use:\r\n"
                L"NTDLLEntryPatch_x32 for x32 processes.\r\n"
                L"NTDLLEntryPatch_x64 for x64 processes.\r\n"
            );
            CloseHandle(hProcess);
            return FALSE;
        }

        if (!patch)
        {
            jmp_itfself[0] = ((unsigned char*)ntdll_ep)[0];
            jmp_itfself[1] = ((unsigned char*)ntdll_ep)[1];
            LogW(
                my_log,
                FALSE,
                LOG_TAG_INFO
                L"Unpatching with: 0x%02X 0x%02X \r\n", jmp_itfself[0], jmp_itfself[1]);
        }
        else
        {
            LogW(
                my_log,
                FALSE,
                LOG_TAG_INFO
                L"Patching with JMP itself: 0x%02X 0x%02X \r\n", jmp_itfself[0], jmp_itfself[1]);
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

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Remote instructions before the patch:\r\n");
        total_bytes = GetBytesInstructionsReplaced(code_before_patch, ntdll_ep, sizeof(jmp_itfself), sizeof(code_before_patch));
        if (patch)
        {
            CheckDangerousInstructions(code_before_patch, ntdll_ep, total_bytes);
        }

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Remote instructions after the patch:\r\n");
        total_bytes = GetBytesInstructionsReplaced(code_after_patch, ntdll_ep, sizeof(jmp_itfself), sizeof(code_after_patch));
        if (!patch)
        {
            CheckDangerousInstructions(code_after_patch, ntdll_ep, total_bytes);
        }

        CloseHandle(hProcess);
    }
    else
    {
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            L"Error openning process\r\n");
    }

    return true;
}