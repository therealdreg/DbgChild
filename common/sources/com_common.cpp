/*
DbgChild - COMMON
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
#include "com_common.h"

/*
TODO:
Refactorize
check memory operations & paths bounds etc
fix possibles buffers overflows, underruns etc.
Documentation
Consistent Variable Names
....
*/

LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)
GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");

GetNativeSystemInfo_t GetNativeSystemInfo_f = (GetNativeSystemInfo_t)GetProcAddress(
    GetModuleHandleW(L"kernel32"), "GetNativeSystemInfo");


BOOL DirExistW(WCHAR* dirName)
{
    DWORD attribs = GetFileAttributesW(dirName);

    if (attribs == INVALID_FILE_ATTRIBUTES)
    {
        return FALSE;
    }

    return (attribs & FILE_ATTRIBUTE_DIRECTORY);
}

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

BOOL Is64BitProcessPID(DWORD pid)
{
    HANDLE process;
    BOOL retf;

    process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    retf = Is64BitProcess(process);

    CloseHandle(process);

    return retf;
}

void GetCurrentPath(WCHAR * current_path)
{
    wchar_t* tmp_ptr;

    ZeroMemory(current_path, sizeof(wchar_t) * MAX_PATH);

    GetModuleFileNameW(GetModuleHandleW(NULL), current_path, sizeof(wchar_t) * MAX_PATH);
    tmp_ptr = current_path;
    tmp_ptr += wcslen(current_path);
    while (tmp_ptr[0] != '\\')
    {
        tmp_ptr--;
    }
    tmp_ptr[1] = 0;
}


BOOL EnableDebugPrivilege()
{
    HANDLE currentProcessToken;
    
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
    
    return SetPrivilegeW(currentProcessToken, L"SeDebugPrivilege", TRUE);
}

BOOL SetPrivilegeW(
    HANDLE hToken,          // access token handle
    LPWSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}