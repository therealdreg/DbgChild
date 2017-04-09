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

#include "stdafx.h"
#include "NewProcessWatcher.h"

#ifdef _WIN64
#error "This program does not support being compiled in x64 mode. Compile for the x32 version only."
#endif


// Definition for undocumented function in kernel32:SetConsoleIcon
typedef void (WINAPI *pSetConsoleIcon)(HICON);
pSetConsoleIcon ProcSetConsoleIcon = NULL;

// Constants for resources used for eye blink
CONST INT ICO_EYEOPEN = 102;
CONST INT ICO_EYEHALF = 103;
CONST INT ICO_EYECLOSED = 104;

// Handles for icons for eye blink
HICON hIcoEyeOpen;
HICON hIcoEyeHalf;
HICON hIcoEyeClosed;

// Used to blink the eye icon
VOID CALLBACK NewProcessWatcherTimerProc(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{

	DWORD dwBlinkDuration = 100;
	ProcSetConsoleIcon(hIcoEyeOpen);
	SleepEx(dwBlinkDuration, FALSE);
	ProcSetConsoleIcon(hIcoEyeHalf);
	SleepEx(dwBlinkDuration, FALSE);
	ProcSetConsoleIcon(hIcoEyeClosed);
	SleepEx(dwBlinkDuration, FALSE);
	ProcSetConsoleIcon(hIcoEyeClosed);
	SleepEx(dwBlinkDuration, FALSE);
	ProcSetConsoleIcon(hIcoEyeHalf);
	SleepEx(dwBlinkDuration, FALSE);
	ProcSetConsoleIcon(hIcoEyeOpen);
	return;
}


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

MY_OWN_LOGW_t* my_log = NULL;

int main(int argc, char** argv)
{

	HMODULE hModKernel32;
	HINSTANCE hMod;
	HANDLE hTimer = NULL;
	HANDLE hQueue = NULL;
	BOOL bSuccess;

	// Get SetConsoleIcon procedure
	hModKernel32 = GetModuleHandle(TEXT("Kernel32.dll"));
	ProcSetConsoleIcon = (pSetConsoleIcon)GetProcAddress(hModKernel32, "SetConsoleIcon");

	// If SetConsoleIcon is available we use it
	if (ProcSetConsoleIcon != NULL)
	{

		// Get module handle and load icons for blinking eye
		hMod = GetModuleHandle(NULL);
		hIcoEyeOpen = LoadIcon(hMod, MAKEINTRESOURCE(ICO_EYEOPEN));
		hIcoEyeHalf = LoadIcon(hMod, MAKEINTRESOURCE(ICO_EYEHALF));
		hIcoEyeClosed = LoadIcon(hMod, MAKEINTRESOURCE(ICO_EYECLOSED));

		// Set initial icon
		ProcSetConsoleIcon(hIcoEyeOpen);

		hQueue = CreateTimerQueue();
		if (hQueue != NULL)
		{
			// Create timer to fire every 5 seconds for eye to blink
			bSuccess = CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK) NewProcessWatcherTimerProc, 0, 5000, 5000, 0);
		}
	}

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
    BOOL old_processes = FALSE;

    if (argc > 1)
    {
        if (tolower(argv[1][0]) == 'o')
        {
            puts("Watching old processes...");
            old_processes = TRUE;
        }
    }

    if (old_processes == FALSE)
    {
        HANDLE hMutex = OpenMutexW(MUTEX_ALL_ACCESS, 0, L"NewProcessWatcherDreg");

        if (!hMutex)
        {
            hMutex = CreateMutexW(0, 0, L"NewProcessWatcherDreg");
        }
        else
        {
            CloseHandle(hMutex);
            MessageBoxW(NULL, L"THERE IS OTHER INSTANCE RUNNING!", L"NewProcessWatcher", MB_ICONERROR);
            return -1;
        }
    }

    WCHAR full_path[MAX_PATH] = { 0 };
    wchar_t x64_full_path[MAX_PATH] = { 0 };
    wchar_t x86_full_path[MAX_PATH] = { 0 };

    GetCurrentPath(full_path);

    wcscpy_s(x86_full_path, full_path);
    wcscpy_s(x64_full_path, full_path);

    wcscat_s(x86_full_path, L"x32\\CPIDS");
    wcscat_s(x64_full_path, L"x64\\CPIDS");

    if (old_processes == TRUE)
    {
        int retf = OldProcesses(x86_full_path, x64_full_path);
        puts("\nPRESS ENTER TO EXIT.\n");
        getchar();
        return retf;
    }

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

int OldProcesses(wchar_t* x86_path, wchar_t* x64_path)
{
    WIN32_FIND_DATAW ffd = { 0 };
    wchar_t* paths[] = { x86_path, x64_path };
    std::vector<HANDLE> array_handle;

    for (int i = 0; i < ARRAYSIZE(paths); i++)
    {
        HANDLE hFind;
        WCHAR actual_path_api_spec[MAX_PATH];

        ZeroMemory(actual_path_api_spec, sizeof(actual_path_api_spec));
        wcscpy_s(actual_path_api_spec, paths[i]);
        wcscat_s(actual_path_api_spec, L"\\*");

        wprintf(L"Watching: %s\n", paths[i]);

        hFind = FindFirstFileW(actual_path_api_spec, &ffd);

        if (INVALID_HANDLE_VALUE == hFind)
        {
            continue;
        }

        do
        {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                wprintf(L"FILE FOUND: %s\n", ffd.cFileName);
                PROCESS_CREATED_PARAMS_t * process_created_params = (PROCESS_CREATED_PARAMS_t *)calloc(1, sizeof(PROCESS_CREATED_PARAMS_t));
                wcscpy_s(process_created_params->file_name, ffd.cFileName);
                wcscpy_s(process_created_params->path, paths[i]);
                array_handle.push_back(
                    CreateThread(
                        NULL,
                        0,
                        ProcesCreated,
                        (LPVOID)process_created_params,
                        0,
                        NULL
                    )
                );
            }
        } while (FindNextFileW(hFind, &ffd) != 0);

        FindClose(hFind);
    }

    printf("Waiting all POST PROCESS Threads to finish...\n");
    for (auto &i : array_handle)
    {
        WaitForSingleObject(i, INFINITE);
    }

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
                                wprintf(L"TID[%d] - New file created/renamed: %s\n", GetCurrentThreadId(), file_name);

                                PROCESS_CREATED_PARAMS_t * process_created_params = (PROCESS_CREATED_PARAMS_t *)calloc(1, sizeof(PROCESS_CREATED_PARAMS_t));
                                wcscpy_s(process_created_params->file_name, file_name);
                                wcscpy_s(process_created_params->path, path_watch);
                                CreateThread(
                                    NULL,
                                    0,
                                    ProcesCreated,
                                    (LPVOID)process_created_params,
                                    0,
                                    NULL
                                );
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

DWORD WINAPI ProcesCreated(_In_ LPVOID lpParameter)
{
    DWORD pid = 0;
    wchar_t full_path[MAX_PATH] = { 0 };
    char* type_pid = NULL;
    PROCESS_CREATED_PARAMS_t* params = (PROCESS_CREATED_PARAMS_t*)lpParameter;

    pid = _wtoi(params->file_name);

    wprintf(L"TID %d PROCESS CREATED: %d\n", GetCurrentThreadId(), pid);

    wcscpy_s(full_path, MAX_PATH, params->path);
    wcscat_s(full_path, MAX_PATH, L"\\");
    wcscat_s(full_path, MAX_PATH, params->file_name);

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

    wprintf(L"TID[%d] - PID: %d from Pre Executed: %s\n", GetCurrentThreadId(), pi.dwProcessId, pre_cmd);

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

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

    PostProcess((LPVOID)pid);

    free(lpParameter);

    return 0;
}

DWORD WINAPI PostProcess(_In_ LPVOID lpParameter)
{
    DWORD pid = (DWORD)lpParameter;
    DWORD main_tid = 0;

    wprintf(L"TID %d POST PROCESS: %d\n", GetCurrentThreadId(), pid);

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

    wprintf(L"TID[%d] - PID: %d from Post Executed: %s\n", GetCurrentThreadId(), pi.dwProcessId, post_cmd);

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}

void ConvertCMDLine(wchar_t* cmd_line, DWORD pid)
{
#pragma warning( push )
#pragma warning(disable:4996)
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
    printf("TID[%d] - printing CMD readed in ASCII, if you can read this, you must change it to unicode: %s\n", GetCurrentThreadId(), (char*)cmd_line);
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