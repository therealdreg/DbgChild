#include "plugin.h"

enum
{
    MENU_HOOK,
    MENU_PATCH_NTDLL,
    MENU_UNPATCH_NTDLL,
    MENU_INFO
};

PLUG_EXPORT void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
    _plugin_logprintf("[" PLUGIN_NAME "] Debugging of %s started!\n", info->szFileName);
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    _plugin_logputs("[" PLUGIN_NAME "] Debugging stopped!");
}

PLUG_EXPORT void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
{
    _plugin_logprintf("[" PLUGIN_NAME "] ExceptionRecord.ExceptionCode: %08X\n", info->Exception->ExceptionRecord.ExceptionCode);
}

PLUG_EXPORT void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
    if(info->DebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        _plugin_logprintf("[" PLUGIN_NAME "] DebugEvent->EXCEPTION_DEBUG_EVENT->%.8X\n", info->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
    }
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

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    if (info->hEntry != MENU_INFO)
    {
        if (!DbgIsDebugging())
        {
            MessageBoxA(hwndDlg, "DONT DEBUGEE OPEN", PLUGIN_NAME, MB_ICONERROR);
            return;
        }
    }

    wchar_t path[MAX_PATH] = { 0 };
    wchar_t exe[MAX_PATH] = { 0 };
    wchar_t args[MAX_PATH] = { 0 };
    wchar_t actual_pid[ARRAYSIZE(L"4294967295")] = { 0 };

    char* dis_cmd = "dis LdrInitializeThunk";

    _itow_s(DbgGetProcessId(), actual_pid, 10);

    GetCurrentPath(path);


    HANDLE hMutex;
    switch(info->hEntry)
    {
        case MENU_HOOK:
            hMutex = OpenMutexW(MUTEX_ALL_ACCESS, 0, L"NewProcessWatcherDreg");
            if (!hMutex)
            {
                ReleaseMutex(hMutex);
                int result = MessageBoxA(NULL, "NewProcessWatcher is not running, do you want launch it?", PLUGIN_NAME, MB_YESNO | MB_ICONQUESTION | MB_TOPMOST);
                if (result == IDYES)
                {
                    WCHAR watcher_path[MAX_PATH] = { 0 };
   
                    wcscpy_s(watcher_path, path);
                    ZeroMemory(&(watcher_path[wcslen(watcher_path) - 4]), 2);
                    wcscat_s(watcher_path, L"NewProcessWatcher.exe");

                    ShellExecuteW(NULL, L"runas", watcher_path, NULL, NULL, SW_SHOWNORMAL);
                }
            }

            wcscpy_s(exe, L"CreateProcessPatch.exe");
            wcscpy_s(args, actual_pid);
            dis_cmd = "dis ZwCreateUserProcess";
            break;

        case MENU_PATCH_NTDLL:
            wcscpy_s(exe, L"NTDLLEntryPatch.exe");
            wcscpy_s(args, actual_pid);
            wcscat_s(args, L" p");
            break;

        case MENU_UNPATCH_NTDLL:
            wcscpy_s(exe, L"NTDLLEntryPatch.exe");
            wcscpy_s(args, actual_pid);
            wcscat_s(args, L" u");
            break;

        case MENU_INFO:
            MessageBoxA(hwndDlg, PLUGIN_NAME " by David Reguera Garcia aka Dreg\ndreg@fr33project.org\nhttps://github.com/David-Reguera-Garcia-Dreg/DbgChild\nhttp://www.fr33project.org", PLUGIN_NAME, MB_ICONINFORMATION);
            break;
    }

    if (info->hEntry != MENU_INFO)
    {
        ShellExecuteW(NULL, L"runas", exe, args, path, SW_SHOWNORMAL);
        DbgCmdExec(dis_cmd);
    }
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here (clearing menus optional).
bool pluginStop()
{
    _plugin_unregistercommand(pluginHandle, PLUGIN_NAME);
    _plugin_menuclear(hMenu);
    return true;
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_HOOK, "&Hook process creation");
    _plugin_menuaddentry(hMenu, MENU_PATCH_NTDLL, "&Patch NTDLL Entry");
    _plugin_menuaddentry(hMenu, MENU_UNPATCH_NTDLL, "&Unpatch NTDLL Entry");
    _plugin_menuaddentry(hMenu, MENU_INFO, "&Plugin Info by Dreg");
}
