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

BOOL FileExistW(WCHAR* filename)
{
    DWORD dwAttrib = GetFileAttributesW(filename);
    if ((dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)))
    {
        return TRUE;
    }

    return FALSE;
}

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
        if (tmp_ptr <= current_path)
        {
            ZeroMemory(current_path, sizeof(wchar_t) * MAX_PATH);
            return;
        }
    }
    tmp_ptr[1] = 0;
}


BOOL EnableDebugPrivilege()
{
    HANDLE currentProcessToken;
    
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);
    
    BOOL retf = SetPrivilegeW(currentProcessToken, L"SeDebugPrivilege", TRUE);

    if (retf)
    {
        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"Enabling debug priv\r\n");
    }
    else
    {
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            L"Enabling debug priv\r\n");
    }

    return retf;
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
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            L"LookupPrivilegeValue error: %u\r\n", GetLastError());
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
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            L"AdjustTokenPrivileges error: %u\r\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            L"The token does not have the specified privilege.\r\n");
        return FALSE;
    }

    return TRUE;
}

void CloseLog(MY_OWN_LOGW_t* my_log)
{
    CloseHandle(my_log->file);

    ZeroMemory(my_log, sizeof(*my_log));
    
    free(my_log);
}

MY_OWN_LOGW_t* CreateLogW(WCHAR* log_path, BOOL show_stdout, BOOL show_stderr)
{
    MY_OWN_LOGW_t* retf = NULL;

    retf = (MY_OWN_LOGW_t*) calloc(1, sizeof(MY_OWN_LOGW_t));
    if (retf != NULL)
    {
        retf->file = CreateFileW(
            log_path,
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0
        );

        retf->show_stdout = show_stdout;
        retf->show_stderr = show_stderr;

        if (retf->file == INVALID_HANDLE_VALUE)
        {
            free(retf);
            retf = NULL;
        }
        else
        {
            DWORD bytes_written;
            unsigned char utf_16_bom[] = { 0xFF, 0xFE };

            WriteFile(retf->file, utf_16_bom, sizeof(utf_16_bom), &bytes_written, NULL);
            FlushFileBuffers(retf->file);
        }
    }

    return retf;
}

void GetLogPath(WCHAR* log_path)
{
    WCHAR actual_path[MAX_PATH];
    wchar_t* tmp_ptr;

    ZeroMemory(log_path, sizeof(WCHAR) * MAX_PATH);

    GetCurrentPath(log_path);
    //bullshit algorithm, very crap here
    tmp_ptr = log_path;
    tmp_ptr += wcslen(log_path);
    do
    {
        ZeroMemory(actual_path, sizeof(WCHAR) * MAX_PATH);
        wcscpy_s(actual_path, log_path);
        wcscat_s(actual_path, L"dbgchildlogs");
        tmp_ptr[0] = 0;
        while (tmp_ptr[0] != '\\')
        {
            tmp_ptr--;
            if (tmp_ptr <= log_path)
            {
                ZeroMemory(log_path, sizeof(wchar_t) * MAX_PATH);
                return;
            }
        }
        tmp_ptr[1] = 0;
    } while (!DirExistW(actual_path));

    ZeroMemory(log_path, sizeof(WCHAR) * MAX_PATH);
    wcscpy_s(log_path, MAX_PATH, actual_path);
    wcscat_s(log_path, MAX_PATH, L"\\");
}

void LogW(MY_OWN_LOGW_t* log, bool is_error, WCHAR* format, ...)
{
    WCHAR* buffer = NULL;
    DWORD bytes_written = 0;
    DWORD bytes_to_write = 0;
    int len = 0;
    bool free_buff = true;
    va_list args;

    va_start(args, format);
    if (my_log != NULL)
    {
        len = _vscwprintf(format, args) + 1;
        buffer = (WCHAR*) calloc(len, sizeof(WCHAR));
        if (buffer == NULL)
        {
            free_buff = false;
            buffer = L"Fail calloc log buffer\r\n";
            len = wcslen(buffer) + 1;
        }
        else
        {
            free_buff = true;
        }

        vswprintf_s(buffer, len, format, args);
        bytes_to_write = (len - 1) * sizeof(WCHAR);
        WriteFile(log->file, buffer, bytes_to_write, &bytes_written, NULL);
        FlushFileBuffers(log->file);

        if (is_error)
        {
            if (log->show_stderr)
            {
                fwprintf(stderr, buffer);
                fflush(stderr);
            }
        }
        else
        {
            if (log->show_stdout)
            {
                wprintf(buffer);
                fflush(stdout);
            }
        }

        if (free_buff)
        {
            free(buffer);
        }
    }
    va_end(args);
}


MY_OWN_LOGW_t* InitLog(wchar_t* component_name)
{
    wchar_t actual_pid[ARRAYSIZE(L"4294967295")] = { 0 };
    wchar_t log_path[MAX_PATH] = { 0 };

    wprintf(L"Searching log path...\n");

    _itow_s(GetCurrentProcessId(), actual_pid, 10);

    GetLogPath(log_path);

    wcscat_s(log_path, component_name);
    wcscat_s(log_path, L".");
    wcscat_s(log_path, actual_pid);
    wcscat_s(log_path, L".unicode.txt");

    wprintf(L"\nlog path: %s\n\n", log_path);

    return CreateLogW(log_path, TRUE, TRUE);
}