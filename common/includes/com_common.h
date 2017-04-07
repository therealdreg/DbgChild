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

#ifndef _COM_COMMON_H__
#define _COM_COMMON_H__

#include <windows.h>
#include <stdio.h>

#define PAGE_SIZE 4096
#define PAGE_ROUND_DOWN(x) (((ULONG_PTR)(x)) & (~(PAGE_SIZE-1)))
#define PAGE_ROUND_UP(x) ( (((ULONG_PTR)(x)) + PAGE_SIZE-1)  & (~(PAGE_SIZE-1)) )

typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

typedef void (WINAPI* GetNativeSystemInfo_t)(
    _Out_ LPSYSTEM_INFO lpSystemInfo
    );

extern LPFN_ISWOW64PROCESS fnIsWow64Process;

extern GetNativeSystemInfo_t GetNativeSystemInfo_f;

#define LOG_TAG_INFO L"TAG_INFO: \r\n"
#define LOG_TAG_ERROR L"TAG_ERROR: \r\n"
#define LOG_TAG_WARNING L"TAG_WARNING: \r\n"
#define LOG_TAG_OK L"TAG_OK: \r\n"

typedef struct
{
    WCHAR full_path[MAX_PATH];
    HANDLE file;
    BOOL show_stdout;
    BOOL show_stderr;
} MY_OWN_LOGW_t;

extern MY_OWN_LOGW_t* my_log;

BOOL FileExistW(WCHAR* filename);

BOOL Is64BitProcess(HANDLE process);

BOOL Is64BitProcessPID(DWORD pid);

BOOL DirExistW(WCHAR* dirName);

void GetCurrentPath(WCHAR * current_path);

BOOL EnableDebugPrivilege();

BOOL SetPrivilegeW(HANDLE hToken, LPWSTR lpszPrivilege, BOOL bEnablePrivilege);

void CloseLog(MY_OWN_LOGW_t* my_log);

WCHAR* GetLogFullPathW(MY_OWN_LOGW_t* log);

void ResumeProcess(HANDLE process);

void SuspendProcess(HANDLE process);

void SuspendProcessPID(DWORD pid);

void ResumeProcessPID(DWORD pid);

MY_OWN_LOGW_t* CreateLogW(WCHAR* log_path, BOOL show_stdout, BOOL show_stderr);

void LogW(MY_OWN_LOGW_t* log, bool is_error, WCHAR* format, ...);

void GetLogPath(WCHAR* log_path);

MY_OWN_LOGW_t* InitLog(wchar_t* component_name);

#endif /* _COM_COMMON_H__ */


