/*
DbgChild - New Process Watcher
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


/*
TODO:
Refactorize
check memory operations & paths bounds etc
fix possibles buffers overflows, underruns etc.
improve this overkill design...
Documentation
Consistent Variable Names
....
*/

#include "stdafx.h"
#include <windows.h>
#include <inttypes.h>
#include <stdint.h>
#include "NewProcessWatcher.h"

#ifdef _WIN64
#error "This program cant works fine compiled in x64 mode. use only x32 version"
#endif


DWORD GetMainTIDFromPID(DWORD pid)
{
    DWORD tid = 0;
    BOOL found = false;

    do
    {
        HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
        THREADENTRY32 te32;

        hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if (hThreadSnap == INVALID_HANDLE_VALUE)
        {
            return tid;
        }

        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hThreadSnap, &te32))
        {
            CloseHandle(hThreadSnap);
            return tid;
        }

        do
        {
            if (te32.th32OwnerProcessID == pid)
            {
                tid = te32.th32ThreadID;
                found = true;
                break;
            }

            Sleep(1);
        } while (Thread32Next(hThreadSnap, &te32));

        CloseHandle(hThreadSnap);

        Sleep(1);
    } while (!found);

    return tid;
}


typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

typedef void (WINAPI* GetNativeSystemInfo_t)(
    _Out_ LPSYSTEM_INFO lpSystemInfo
    );

LPFN_ISWOW64PROCESS fnIsWow64Process_f = (LPFN_ISWOW64PROCESS)
GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");

GetNativeSystemInfo_t GetNativeSystemInfo_f = (GetNativeSystemInfo_t)GetProcAddress(
    GetModuleHandleW(L"kernel32"), "GetNativeSystemInfo");

BOOL Is64BitProcess(HANDLE process)
{
    SYSTEM_INFO si = { 0 };
    BOOL isWow64 = FALSE;

    if (GetNativeSystemInfo_f == NULL || fnIsWow64Process_f == NULL)
    {
        return FALSE;
    }

    GetNativeSystemInfo_f(&si);
    if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
    {
        return FALSE;
    }

    fnIsWow64Process_f(process, &isWow64);

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

void ConvertCMDLine(wchar_t* cmd_line, DWORD pid)
{
#pragma warning( push )
#pragma warning(disable:4996)

#define MAGIC_PID_W (L"4294967295")
#define SIZE_MAGIC_PID_W (ARRAYSIZE(MAGIC_PID_W) - 1)

    wchar_t* pid_str = cmd_line;
    wchar_t* pid_end_str = NULL;
    WCHAR actual_pid[SIZE_MAGIC_PID_W + 1] = { 0 };

    //REMOVE UTF BOM
    if (((unsigned char*)cmd_line)[0] == 0xFF && ((unsigned char*)cmd_line)[1] == 0xFE)
    {
        wprintf(L"TID[%d] - Removing UTF-BOM in CMD LINE\n", GetCurrentThreadId());
        wcscpy(cmd_line, cmd_line + 1);
    }

    _itow_s(pid, actual_pid, 10);
    DWORD size_actual_pid = wcslen(actual_pid);
    do
    {
        pid_str = wcsstr(pid_str, MAGIC_PID_W);
        if (pid_str != NULL)
        {
            wcscpy(pid_str, actual_pid);
            pid_end_str = pid_str + SIZE_MAGIC_PID_W;
            pid_str += size_actual_pid;
            wcscpy(pid_str, pid_end_str);
        }
    } while (pid_str != NULL);

#pragma warning( pop )
}

void GetCmdFromFileW(wchar_t* file, wchar_t* cmd_line, DWORD pid)
{
    HANDLE hFile = CreateFileW(
        file,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    DWORD bytes_readed = 0;
  
    ZeroMemory(cmd_line, sizeof(wchar_t) * MAX_PATH);

    wprintf(L"ID[%d] - Reading: %s\n", GetCurrentThreadId(), file);
    ReadFile(hFile, cmd_line, (sizeof(wchar_t) * MAX_PATH) - 2, &bytes_readed, NULL);
    printf("TID[%d] - printing CMD readed in ASCII, if you can read this, you must change it to unicode: %s\n", GetCurrentThreadId(), (char*) cmd_line);
    wprintf(L"TID[%d] - RAW CMD LINE READED: %s\n", GetCurrentThreadId(), cmd_line);
    ConvertCMDLine(cmd_line, pid);
    wprintf(L"TID[%d] - CMD LINE CONVERTED: %s\n", GetCurrentThreadId(), cmd_line);


    CloseHandle(hFile);
}

void GetPreResumedCmd(WCHAR * pre_resumed_cmd, DWORD pid, bool x64)
{
    WCHAR current_path[MAX_PATH] = { 0 };

    ZeroMemory(pre_resumed_cmd, sizeof(wchar_t) * MAX_PATH);

    GetCurrentPath(current_path);
    if (x64)
    { 
        wcscat_s(current_path, L"x64_pre.unicode.txt");
    }
    else
    {
        wcscat_s(current_path, L"x86_pre.unicode.txt");
    }

    GetCmdFromFileW(current_path, pre_resumed_cmd, pid);
}

void GetPostResumedCmd(WCHAR * post_resumed_cmd, DWORD pid, bool x64)
{
    WCHAR current_path[MAX_PATH] = { 0 };

    ZeroMemory(post_resumed_cmd, sizeof(wchar_t) * MAX_PATH);

    GetCurrentPath(current_path);
    if (x64)
    {
        wcscat_s(current_path, L"x64_post.unicode.txt");
    }
    else
    {
        wcscat_s(current_path, L"x86_post.unicode.txt");
    }

    GetCmdFromFileW(current_path, post_resumed_cmd, pid);
}

DWORD WINAPI PostProcess(_In_ LPVOID lpParameter)
{
    DWORD pid = (DWORD)lpParameter;
    DWORD main_tid = 0;

    wprintf(L"TID %d Created! - POST PROCESS: %d\n", GetCurrentThreadId(), pid);

    main_tid = GetMainTIDFromPID(pid);

    printf("TID[%d] - Detected in PID %d , Main TID %d \n", GetCurrentThreadId(), pid, main_tid);

    BOOL b_Suspend;
    int i = 0;
    do
    {
        b_Suspend = FALSE;
        {
            cProcInfo i_Proc;
            DWORD u32_Error = i_Proc.Capture();
            SYSTEM_PROCESS* pk_Proc = i_Proc.FindProcessByPid(pid);
            SYSTEM_THREAD* pk_Thread = i_Proc.FindThreadByTid(pk_Proc, main_tid);
            i_Proc.IsThreadSuspended(pk_Thread, &b_Suspend);

            if (b_Suspend)
            {
                if ((i % 10) == 0)
                {
                    printf("TID[%d] - Main TID %d is suspended yet, try: %d\n", GetCurrentThreadId(), main_tid, i);
                }
                i++;
                Sleep(500);
            }
        }
    } while (b_Suspend);

    printf("TID[%d] - Main TID %d is Running!!, total tries %d\n", GetCurrentThreadId(), main_tid, i++);

    WCHAR post_cmd[MAX_PATH];

    if (Is64BitProcessPID(pid))
    {
        GetPostResumedCmd(post_cmd, pid, true);
    }
    else
    {
        GetPostResumedCmd(post_cmd, pid, false);
    }

    STARTUPINFOW sp = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    sp.cb = sizeof(STARTUPINFOW);

    CreateProcessW(
        NULL,
        post_cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &sp,
        &pi
    );

    WaitForSingleObject(pi.hProcess, INFINITE);

    return 0;
}

DWORD ProcesCreated(wchar_t * file_name, wchar_t * path)
{
    DWORD pid = _wtoi(file_name);
    wchar_t * full_path = (wchar_t*) calloc(1, sizeof(wchar_t) * MAX_PATH);
    char* type_pid = NULL;

    wcscpy_s(full_path, MAX_PATH, path);
    wcscat_s(full_path, MAX_PATH, L"\\");
    wcscat_s(full_path, MAX_PATH, file_name);

    wprintf(L"TID[%d] - Created PID: %d - FULL PATH: %s\n", GetCurrentThreadId(), pid, full_path);
    WCHAR pre_cmd[MAX_PATH];

    if (Is64BitProcessPID(pid))
    {
        type_pid = "x64";
        GetPreResumedCmd(pre_cmd, pid, true);
    }
    else
    {
        type_pid = "x32";
        GetPreResumedCmd(pre_cmd, pid, false);
    }

    STARTUPINFOW sp = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    sp.cb = sizeof(STARTUPINFOW);

    CreateProcessW(
        NULL, 
        pre_cmd, 
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &sp,
        &pi
    );

    WaitForSingleObject(pi.hProcess, INFINITE);

    HANDLE hFile = CreateFileW(
        full_path,                // name of the write
        GENERIC_WRITE,          // open for writing
        FILE_SHARE_READ,                      // do not share
        NULL,                   // default security
        OPEN_EXISTING,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no

    DWORD bytes_written;

    WriteFile(hFile, type_pid, strlen(type_pid) + 1, &bytes_written, NULL);

    CloseHandle(hFile);

    CreateThread(
        NULL,
        0,
        PostProcess,
        (LPVOID) pid,
        0,
        NULL
    );

    
    return 0;
}

DWORD WINAPI NewProcessWatcher(_In_ LPVOID lpParameter)
{
    wchar_t* path_watch = (wchar_t *)lpParameter;

    wprintf(L"TID %d Created! - %s\n", GetCurrentThreadId(), path_watch);

    HANDLE hDir = CreateFileW(
        path_watch,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hDir != NULL)
    {
        FILE_NOTIFY_INFORMATION* FileNotifyInfo = (FILE_NOTIFY_INFORMATION*)calloc(1, 4096);
        do
        {
            DWORD dwBytesReturned = 0;
            ZeroMemory(FileNotifyInfo, 4096);
            
            wprintf(L"TID[%d] - Watching: %s\n", GetCurrentThreadId(), path_watch);
            if (ReadDirectoryChangesW(
                hDir,
                (LPVOID)FileNotifyInfo,
                4096,
                FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME,
                &dwBytesReturned,
                NULL,
                NULL
            ) == 0)
            {
                fprintf(stderr, "\n TID[%d] - ERROR: ReadDirectoryChangesW. \n", GetCurrentThreadId());
            }
            else
            {
                /*
                TODO: ADD OVERFLOW DETECTION:
                When you first call ReadDirectoryChangesW, the system allocates a buffer to store
                change information. This buffer is associated with the directory handle until it is closed
                and its size does not change during its lifetime. Directory changes that occur between calls
                to this function are added to the buffer and then returned with the next call. If the buffer
                overflows, the entire contents of the buffer are discarded, the lpBytesReturned parameter
                contains zero, and the ReadDirectoryChangesW function fails with the error code ERROR_NOTIFY_ENUM_DIR.
                */
                if (dwBytesReturned != 0)
                {
                    FILE_NOTIFY_INFORMATION* actual_FileNotifyInfo = FileNotifyInfo;
                    FILE_NOTIFY_INFORMATION* next_FileNotifyInfo = FileNotifyInfo;
                    do
                    {
                        actual_FileNotifyInfo = next_FileNotifyInfo;
                        if (actual_FileNotifyInfo->FileNameLength != 0
                            &&
                            (
                                actual_FileNotifyInfo->Action == FILE_ACTION_ADDED ||
                                actual_FileNotifyInfo->Action == FILE_ACTION_RENAMED_NEW_NAME
                                )
                            )
                        {
                            WCHAR file_name[MAX_PATH] = { 0 };

                            printf("TID[%d] - Accepted event type: %d\n", GetCurrentThreadId(), actual_FileNotifyInfo->Action);
                            if (sizeof(file_name) - 2 >= actual_FileNotifyInfo->FileNameLength)
                            {
                                memcpy(file_name, actual_FileNotifyInfo->FileName, actual_FileNotifyInfo->FileNameLength);
                                wprintf(L"TID[%d] - New file created/renamed: %s\n", GetCurrentThreadId() , file_name);
                                ProcesCreated(file_name, path_watch);
                            }
                            else
                            {
                                fprintf(stderr, "TID[%d] - ERROR: FILE NAME CREATED TOO BIG\n", GetCurrentThreadId());
                            }
                        }
                        else
                        {
                            printf("TID[%d] - Skipping event type: %d\n", GetCurrentThreadId(), actual_FileNotifyInfo->Action);
                        }

                        next_FileNotifyInfo = (FILE_NOTIFY_INFORMATION*)(((unsigned char*)actual_FileNotifyInfo) + actual_FileNotifyInfo->NextEntryOffset);
                    } while (actual_FileNotifyInfo->NextEntryOffset != 0);
                }
            }
        } while (true);

        CloseHandle(hDir);
    }

    return 0;
}

int main()
{
    puts("\n"
        "DbgChild - New Process Watcher\n"
        "-\n"
        "MIT License\n"
        "-\n"
        "Copyright (c) <2017> <David Reguera Garcia aka Dreg>\n"
        "http://www.fr33project.org/\n"
        "https://github.com/David-Reguera-Garcia-Dreg\n"
        "dreg@fr33project.org\n"
    );

    HANDLE hMutex = OpenMutexW(MUTEX_ALL_ACCESS, 0, L"NewProcessWatcherDreg");

    if (!hMutex)
    {
        hMutex = CreateMutexW(0, 0, L"NewProcessWatcherDreg");
    }
    else
    {
        MessageBoxW(NULL, L"THERE IS OTHER INSTANCE RUNNING!", L"NewProcessWatcher", MB_ICONERROR);
        return -1;
    }

    WCHAR full_path[MAX_PATH] = { 0 };
    wchar_t x64_full_path[MAX_PATH] = { 0 };
    wchar_t x86_full_path[MAX_PATH] = { 0 };

    GetCurrentPath(full_path);

    wcscpy_s(x86_full_path, full_path);
    wcscpy_s(x64_full_path, full_path);

    wcscat_s(x86_full_path, L"x32\\CPIDS");
    wcscat_s(x64_full_path, L"x64\\CPIDS");

    HANDLE x86_thread = CreateThread(
        NULL,
        0,
        NewProcessWatcher,
        x86_full_path,
        0,
        NULL
    );

    HANDLE x64_thread = CreateThread(
        NULL,
        0,
        NewProcessWatcher,
        x64_full_path,
        0,
        NULL
    );

    WaitForSingleObject(x64_thread, INFINITE);
    WaitForSingleObject(x86_thread, INFINITE);

    return 0;
}

