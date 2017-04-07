#include "plugin.h"
#include "icons.h"
#include "com_common.h"

#ifdef _WIN64
#define POST_TXT L"x64_post.unicode.txt"
#define PRE_TXT L"x64_pre.unicode.txt"
#define ARCH_TXT "x64"
#define OTHER_ARCH_TXT "x32"
#else
#define ARCH_TXT "x32"
#define OTHER_ARCH_TXT "x64"
#define POST_TXT L"x86_post.unicode.txt"
#define PRE_TXT L"x86_pre.unicode.txt"
#endif


MY_OWN_LOGW_t * my_log;



const int IDD_DIALOG1 = 101;
const int IDC_EDIT1 = 1001;
const int IDC_BTNOK = 1002;
const int IDC_BTNCANCEL = 1003;

const int IDI_ICON1 = 102;

HINSTANCE hInstance = 0;

static duint processEntry;

enum
{
    MENU_HOOK,
    MENU_CREATE_CPID,
    MENU_OPENLOGS,
    MENU_CLEARLOGS,
    MENU_REMOTE_HOOK,
    MENU_REMOTE_NTDLL_PATCH,
    MENU_REMOTE_NTDLL_UNPATCH,
    MENU_AUTO_HOOK,
    MENU_EDIT_PRE,
    MENU_EDIT_POST,
    MENU_CLEAR,
    MENU_OPENCPIDS,
    MENU_PATCH_NTDLL,
    MENU_UNPATCH_NTDLL,
    MENU_AUTO_UNPATCH_NTDLL,
    MENU_NEW_PROCESS_WATCHER,
    MENU_NEW_PROCESS_WATCHER_OLD,
    MENU_NEW_PROCESS_WATCHER_NO_ASK,
    MENU_GO_TO_HOOK,
    MENU_GO_TO_NTDLL,
    MENU_HELP,
    MENU_INFO
};

PLUG_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        hInstance = hinstDLL;
    }
    return TRUE;
}

PLUG_EXPORT void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
}

PLUG_EXPORT void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
{
}

PLUG_EXPORT void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
}

void ExecuteNewProcessLauncher(BOOL old_process, wchar_t* path)
{
    int result = IDCANCEL;
    WCHAR * params = NULL;
    HANDLE hMutex;

    if (old_process)
    {
        result = IDYES;
        params = L"o";
    }
    else
    {
        hMutex = OpenMutexW(MUTEX_ALL_ACCESS, 0, L"NewProcessWatcherDreg");
        if (!hMutex)
        {
            char rd_value[MAX_PATH] = { 0 };
            ReleaseMutex(hMutex);

            result = 0;
            if (BridgeSettingGet("dbgchild", "watcher_no_ask", rd_value))
            {
                if (strcmp(rd_value, "true") == 0)
                {
                    result = IDYES;
                }
            }
            if (result == 0)
            {
                result = MessageBoxA(NULL, "NewProcessWatcher is not running, do you want launch it?", PLUGIN_NAME, MB_YESNO | MB_ICONQUESTION | MB_TOPMOST);
            }
        }
        else
        {
            _plugin_logprintf("[" PLUGIN_NAME "] NewProcessWatcher already Open");
        }
    }

    if (result == IDYES)
    {
        WCHAR watcher_path[MAX_PATH] = { 0 };

        wcscpy_s(watcher_path, path);
        ZeroMemory(&(watcher_path[wcslen(watcher_path) - 4]), 2);
        wcscat_s(watcher_path, L"NewProcessWatcher.exe");

        ShellExecuteW(NULL, L"runas", watcher_path, params, NULL, SW_SHOWNORMAL);
    }
}


PLUG_EXPORT void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
{
    char rd_value[MAX_PATH] = { 0 };
    bool auto_enable = true;

    if (BridgeSettingGet("dbgchild", "auto_unpatch_ntdll", rd_value))
    {
        if (strcmp(rd_value, "true") == 0)
        {
            auto_enable = true;
        }
        else
        {
            auto_enable = false;
        }
    }

    processEntry = Script::Module::EntryFromAddr(duint(info->CreateProcessInfo->lpBaseOfImage));

    if (auto_enable)
    {
        WCHAR cpids_x32_path[MAX_PATH] = { 0 };
        WCHAR cpids_x64_path[MAX_PATH] = { 0 };
        WCHAR cur_path[MAX_PATH] = { 0 };
        WCHAR exe[MAX_PATH] = { 0 };
        WCHAR args[MAX_PATH] = { 0 };
        wchar_t actual_pid[ARRAYSIZE(L"4294967295")] = { 0 };

        DbgCmdExecDirect("bc LdrInitializeThunk");
        DbgCmdExecDirect("dis LdrInitializeThunk");

        _itow_s(DbgGetProcessId(), actual_pid, 10);

        GetCurrentPath(cpids_x32_path);

        wcscpy_s(exe, cpids_x32_path);
        wcscpy_s(cur_path, cpids_x32_path);
        wcscpy_s(exe, L"NTDLLEntryPatch.exe");
        wcscpy_s(args, actual_pid);
        wcscat_s(args, L" u");

        ZeroMemory(&(cpids_x32_path[wcslen(cpids_x32_path) - 4]), 2);

        wcscpy_s(cpids_x64_path, cpids_x32_path);

        wcscat_s(cpids_x32_path, L"x32\\CPIDS\\");
        wcscat_s(cpids_x32_path, actual_pid);

        wcscat_s(cpids_x64_path, L"x64\\CPIDS\\");
        wcscat_s(cpids_x64_path, actual_pid);

        if (FileExistW(cpids_x32_path) || FileExistW(cpids_x64_path))
        {
            ShellExecuteW(NULL, L"runas", exe, args, cur_path, SW_SHOWNORMAL);
        }
    }

    if (BridgeSettingGet("dbgchild", "auto_hook", rd_value))
    {
        if (strcmp(rd_value, "true") == 0)
        {
            auto_enable = true;
        }
        else
        {
            auto_enable = false;
        }

        if (auto_enable)
        {
            WCHAR exe[MAX_PATH] = { 0 };
            WCHAR path[MAX_PATH] = { 0 };
            WCHAR args[MAX_PATH] = { 0 };
            wchar_t actual_pid[ARRAYSIZE(L"4294967295")] = { 0 };

            _itow_s(DbgGetProcessId(), actual_pid, 10);

            GetCurrentPath(path);

            DbgCmdExecDirect("bc ZwCreateUserProcess");

            ExecuteNewProcessLauncher(FALSE, path);

            wcscpy_s(exe, L"CreateProcessPatch.exe");

            wcscpy_s(args, actual_pid);

            ShellExecuteW(NULL, L"runas", exe, args, path, SW_SHOWNORMAL);
        }
    }
}

INT_PTR CALLBACK GetPIDDialogProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    int nPid = 0;
    HWND hPIDText = 0;

    switch (uMsg)
    {
    case WM_INITDIALOG:
        HICON hIcon;

        hIcon = (HICON)LoadImageW(hInstance,
            MAKEINTRESOURCEW(IDI_ICON1),
            IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON),
            GetSystemMetrics(SM_CYSMICON),
            0);

        if (hIcon)
        {
            SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
        }


        hPIDText = GetDlgItem(hWnd, IDC_EDIT1);
        SendMessageW(hPIDText, EM_LIMITTEXT, 16, NULL);
        PostMessageW(hWnd, WM_NEXTDLGCTL, (WPARAM)hPIDText, TRUE);

        return TRUE;

    case WM_CLOSE:
        EndDialog(hWnd, 0);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BTNOK:
            nPid = GetDlgItemInt(hWnd, IDC_EDIT1, FALSE, FALSE);
            EndDialog(hWnd, nPid);
            break;
        case IDC_BTNCANCEL:
            EndDialog(hWnd, 0);
        }
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

void GetPIDFromUserDialogW(wchar_t * out_pid_str)
{
    int ReturnVal = 0;

    ZeroMemory(out_pid_str, sizeof(L"4294967295"));

    ReturnVal = DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_DIALOG1), hwndDlg, GetPIDDialogProc, NULL);
    if (ReturnVal != -1 && ReturnVal > 0)
    {
        _itow_s((DWORD)ReturnVal, out_pid_str, ARRAYSIZE(L"4294967295"), 10);
    }
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    if (info->hEntry != MENU_INFO &&
        info->hEntry != MENU_HELP &&
        info->hEntry != MENU_NEW_PROCESS_WATCHER &&
        info->hEntry != MENU_NEW_PROCESS_WATCHER_OLD &&
        info->hEntry != MENU_CLEAR &&
        info->hEntry != MENU_AUTO_UNPATCH_NTDLL &&
        info->hEntry != MENU_AUTO_HOOK &&
        info->hEntry != MENU_NEW_PROCESS_WATCHER_NO_ASK &&
        info->hEntry != MENU_EDIT_PRE &&
        info->hEntry != MENU_EDIT_POST &&
        info->hEntry != MENU_OPENCPIDS && 
        info->hEntry != MENU_REMOTE_HOOK &&
        info->hEntry != MENU_REMOTE_NTDLL_PATCH &&
        info->hEntry != MENU_REMOTE_NTDLL_UNPATCH &&
        info->hEntry != MENU_CREATE_CPID &&
        info->hEntry != MENU_OPENLOGS &&
        info->hEntry != MENU_CLEARLOGS
        )
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
    wchar_t* op_type = L"runas";

    char* dis_cmd = NULL;
    duint breakEntry = 0;

    _itow_s(DbgGetProcessId(), actual_pid, 10);

    GetCurrentPath(path);

    switch (info->hEntry)
    {
    case MENU_HOOK:
        DbgCmdExecDirect("bc ZwCreateUserProcess");

        ExecuteNewProcessLauncher(FALSE, path);

        wcscpy_s(exe, L"CreateProcessPatch.exe");
        wcscpy_s(args, actual_pid);
        dis_cmd = "dis ZwCreateUserProcess";
        break;

    case MENU_REMOTE_HOOK:
        ExecuteNewProcessLauncher(FALSE, path);

        GetPIDFromUserDialogW(actual_pid);
        if (
            Is64BitProcess(GetCurrentProcess()) 
            != 
            Is64BitProcessPID(_wtoi(actual_pid))
           )
        {
            MessageBoxA(hwndDlg, 
                "Error: You can only use " ARCH_TXT 
                " for " ARCH_TXT " processes. You must use the " 
                OTHER_ARCH_TXT " debugger/plugin version for this process."
                
                , PLUGIN_NAME, MB_ICONERROR);
        }
        else
        { 
            wcscpy_s(exe, L"CreateProcessPatch.exe");
            wcscpy_s(args, actual_pid);
        }
        
        break;

    case MENU_REMOTE_NTDLL_PATCH:
        GetPIDFromUserDialogW(actual_pid);
        if (
            Is64BitProcess(GetCurrentProcess())
            !=
            Is64BitProcessPID(_wtoi(actual_pid))
            )
        {
            MessageBoxA(hwndDlg,
                "Error: You can only use " ARCH_TXT
                " for " ARCH_TXT " processes. You must use the "
                OTHER_ARCH_TXT " debugger/plugin version for this process."

                , PLUGIN_NAME, MB_ICONERROR);
        }
        else
        {
            wcscpy_s(exe, L"NTDLLEntryPatch.exe");
            wcscpy_s(args, actual_pid);
            wcscat_s(args, L" p");
        }
        break;

    case MENU_REMOTE_NTDLL_UNPATCH:
        GetPIDFromUserDialogW(actual_pid);
        if (
            Is64BitProcess(GetCurrentProcess())
            !=
            Is64BitProcessPID(_wtoi(actual_pid))
            )
        {
            MessageBoxA(hwndDlg,
                "Error: You can only use " ARCH_TXT
                " for " ARCH_TXT " processes. You must use the "
                OTHER_ARCH_TXT " debugger/plugin version for this process."

                , PLUGIN_NAME, MB_ICONERROR);
        }
        else
        {
            wcscpy_s(exe, L"NTDLLEntryPatch.exe");
            wcscpy_s(args, actual_pid);
            wcscat_s(args, L" u");
        }
        break;

    case MENU_EDIT_PRE:
        op_type = L"edit";
        wcscpy_s(exe, path);
        ZeroMemory(&(exe[wcslen(exe) - 4]), 2);
        wcscat_s(exe, PRE_TXT);
        break;

    case MENU_EDIT_POST:
        op_type = L"edit";
        wcscpy_s(exe, path);
        ZeroMemory(&(exe[wcslen(exe) - 4]), 2);
        wcscat_s(exe, POST_TXT);
        break;

    case MENU_CREATE_CPID:
        GetPIDFromUserDialogW(actual_pid);
        wcscat_s(path, L"CPIDS\\");
        wcscat_s(path, actual_pid);
        CloseHandle(CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        ));
        break;

    case MENU_OPENCPIDS:
        op_type = L"explore";
        wcscpy_s(exe, path);
        wcscat_s(exe, L"CPIDS");
        break;

    case MENU_OPENLOGS:
        op_type = L"explore";
        GetLogPath(exe);
        break;
        
    case MENU_CLEARLOGS:
    {
        WCHAR find_path[MAX_PATH] = { 0 };
        WIN32_FIND_DATAW fd;
        HANDLE hFind;
        WCHAR actual_file[MAX_PATH];

        GetLogPath(path);
        GetLogPath(find_path);
        wcscat_s(find_path, L"*");

        hFind = FindFirstFileW(find_path, &fd);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                ZeroMemory(actual_file, sizeof(actual_file));
                wcscpy_s(actual_file, path);
                wcscat_s(actual_file, fd.cFileName);
                DeleteFileW(actual_file);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
        break;

    case MENU_NEW_PROCESS_WATCHER_NO_ASK:
    {
        char rd_value[MAX_PATH] = { 0 };

        if (BridgeSettingGet("dbgchild", "watcher_no_ask", rd_value))
        {
            bool auto_enable = true;
            if (strcmp(rd_value, "true") == 0)
            {
                auto_enable = true;
            }
            else
            {
                auto_enable = false;
            }
            if (auto_enable)
            {
                BridgeSettingSet("dbgchild", "watcher_no_ask", "false");
            }
            else
            {
                BridgeSettingSet("dbgchild", "watcher_no_ask", "true");
            }
            _plugin_menuentrysetchecked(pluginHandle, MENU_NEW_PROCESS_WATCHER_NO_ASK, auto_enable ? false : true);

            BridgeSettingFlush();
        }
    }
    break;

    case MENU_AUTO_UNPATCH_NTDLL:
    {
        char rd_value[MAX_PATH] = { 0 };

        if (BridgeSettingGet("dbgchild", "auto_unpatch_ntdll", rd_value))
        {
            bool auto_enable = true;
            if (strcmp(rd_value, "true") == 0)
            {
                auto_enable = true;
            }
            else
            {
                auto_enable = false;
            }
            if (auto_enable)
            {
                BridgeSettingSet("dbgchild", "auto_unpatch_ntdll", "false");
            }
            else
            {
                BridgeSettingSet("dbgchild", "auto_unpatch_ntdll", "true");
            }
            _plugin_menuentrysetchecked(pluginHandle, MENU_AUTO_UNPATCH_NTDLL, auto_enable ? false : true);

            BridgeSettingFlush();
        }
    }
    break;

    case MENU_AUTO_HOOK:
    {
        char rd_value[MAX_PATH] = { 0 };

        if (BridgeSettingGet("dbgchild", "auto_hook", rd_value))
        {
            bool auto_enable = false;
            if (strcmp(rd_value, "true") == 0)
            {
                auto_enable = true;
            }
            else
            {
                auto_enable = false;
            }
            if (auto_enable)
            {
                BridgeSettingSet("dbgchild", "auto_hook", "false");
            }
            else
            {
                BridgeSettingSet("dbgchild", "auto_hook", "true");
            }
            _plugin_menuentrysetchecked(pluginHandle, MENU_AUTO_HOOK, auto_enable ? false : true);

            BridgeSettingFlush();
        }
    }
    break;

    case MENU_CLEAR:
    {
        WCHAR find_path[MAX_PATH] = { 0 };
        WIN32_FIND_DATAW fd;
        HANDLE hFind;
        WCHAR actual_file[MAX_PATH];

        wcscpy_s(find_path, path);
        wcscat_s(find_path, L"CPIDS\\*");

        hFind = FindFirstFileW(find_path, &fd);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                ZeroMemory(actual_file, sizeof(actual_file));
                wcscpy_s(actual_file, path);
                wcscat_s(actual_file, L"CPIDS\\");
                wcscat_s(actual_file, fd.cFileName);
                DeleteFileW(actual_file);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }
    break;

    case MENU_PATCH_NTDLL:
        DbgCmdExecDirect("bc LdrInitializeThunk");

        wcscpy_s(exe, L"NTDLLEntryPatch.exe");
        wcscpy_s(args, actual_pid);
        wcscat_s(args, L" p");
        dis_cmd = "dis LdrInitializeThunk";
        break;

    case MENU_UNPATCH_NTDLL:
        DbgCmdExecDirect("bc LdrInitializeThunk");

        wcscpy_s(exe, L"NTDLLEntryPatch.exe");
        wcscpy_s(args, actual_pid);
        wcscat_s(args, L" u");
        dis_cmd = "dis LdrInitializeThunk";

        if (BridgeSettingGetUint("Events", "EntryBreakpoint", &breakEntry) && breakEntry)
        {
            char cmd[32] = "";
            sprintf_s(cmd, "bp %p, ss", processEntry);
            DbgCmdExecDirect(cmd);
        }
        break;

    case MENU_NEW_PROCESS_WATCHER:
        ExecuteNewProcessLauncher(FALSE, path);
        break;

    case MENU_NEW_PROCESS_WATCHER_OLD:
        ExecuteNewProcessLauncher(TRUE, path);
        break;

    case MENU_GO_TO_HOOK:
        dis_cmd = "dis ZwCreateUserProcess";
        break;

    case MENU_GO_TO_NTDLL:
        dis_cmd = "dis LdrInitializeThunk";
        break;

    case MENU_HELP:
        op_type = L"open";
        wcscpy_s(exe, path);
        ZeroMemory(&(exe[wcslen(exe) - 4]), 2);
        wcscat_s(exe, L"readme_dbgchild.txt");
        break;

    case MENU_INFO:
        MessageBoxA(hwndDlg, 
            PLUGIN_NAME " by David Reguera Garcia aka Dreg\n"
            "dreg@fr33project.org\n"
            "\n"
            "Site:\n"
            "   https://github.com/David-Reguera-Garcia-Dreg/DbgChild\n"
            "   http://www.fr33project.org\n"
            "\n"
            "Credits:\n"
            "   mrfearless: ICONS & GUI stuff\n"
            "\n"
            "Donations:\n"
            "\n"
            "   -\n\n"
            , PLUGIN_NAME, MB_ICONINFORMATION);
        break;
    }

    if (info->hEntry == MENU_HOOK ||
        info->hEntry == MENU_PATCH_NTDLL ||
        info->hEntry == MENU_UNPATCH_NTDLL ||
        info->hEntry == MENU_HELP ||
        info->hEntry == MENU_EDIT_PRE ||
        info->hEntry == MENU_EDIT_POST ||
        info->hEntry == MENU_OPENCPIDS ||
        info->hEntry == MENU_REMOTE_HOOK ||
        info->hEntry == MENU_REMOTE_NTDLL_PATCH ||
        info->hEntry == MENU_REMOTE_NTDLL_UNPATCH ||
        info->hEntry == MENU_OPENLOGS
        )
    {
        ShellExecuteW(NULL, op_type, exe, args, path, SW_SHOWNORMAL);
    }

    if (dis_cmd != NULL)
    {
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

//HWND hwndDlg = 0;

//Do GUI/Menu related things here.
void pluginSetup()
{

    // Icons
    ICONDATA dbgchild_menu_icon;
    ICONDATA hookprocess_menu_icon;
    ICONDATA patchntdll_menu_icon;
    ICONDATA unpatchntdll_menu_icon;
    ICONDATA newprocesswatcher_menu_icon;
    ICONDATA gotohook_menu_icon;
    ICONDATA gotontdll_menu_icon;
    ICONDATA helpicon_menu_icon;
    ICONDATA clearcpids_menu_icon;
    ICONDATA browsecpids_menu_icon;
	ICONDATA addcpids_menu_icon;
    ICONDATA editresumedicon_menu_icon;
    ICONDATA editsuspendedicon_menu_icon;
	ICONDATA remoteprocesshook_menu_icon;
	ICONDATA remotentdllpatch_menu_icon;
	ICONDATA remotentdllunpatch_menu_icon;
	ICONDATA openlogs_menu_icon;
	ICONDATA clearlogs_menu_icon;

    dbgchild_menu_icon.data = DbgChildIcon;
    dbgchild_menu_icon.size = sizeof(DbgChildIcon);

    hookprocess_menu_icon.data = HookProcessIcon;
    hookprocess_menu_icon.size = sizeof(HookProcessIcon);

    clearcpids_menu_icon.data = ClearCPIDSIcon;
    clearcpids_menu_icon.size = sizeof(ClearCPIDSIcon);
    browsecpids_menu_icon.data = BrowseCPIDSIcon;
    browsecpids_menu_icon.size = sizeof(BrowseCPIDSIcon);
	addcpids_menu_icon.data = AddCPIDSIcon;
	addcpids_menu_icon.size = sizeof(AddCPIDSIcon);	
	
    patchntdll_menu_icon.data = patchNTDLLIcon;
    patchntdll_menu_icon.size = sizeof(patchNTDLLIcon);
    unpatchntdll_menu_icon.data = unpatchNTDLLIcon;
    unpatchntdll_menu_icon.size = sizeof(unpatchNTDLLIcon);
	
    newprocesswatcher_menu_icon.data = NewProcessWatcherIcon;
    newprocesswatcher_menu_icon.size = sizeof(NewProcessWatcherIcon);
	
    gotohook_menu_icon.data = GotoHookIcon;
    gotohook_menu_icon.size = sizeof(GotoHookIcon);
    gotontdll_menu_icon.data = GotoNTDLLIcon;
    gotontdll_menu_icon.size = sizeof(GotoNTDLLIcon);

    editsuspendedicon_menu_icon.data = EditSuspendedIcon;
    editsuspendedicon_menu_icon.size = sizeof(EditSuspendedIcon);
    editresumedicon_menu_icon.data = EditResumedIcon;
    editresumedicon_menu_icon.size = sizeof(EditResumedIcon);
	
	remoteprocesshook_menu_icon.data = RemoteHookProcessIcon;
	remoteprocesshook_menu_icon.size = sizeof(RemoteHookProcessIcon);
	remotentdllpatch_menu_icon.data = RemoteNTDLLPatchIcon;
	remotentdllpatch_menu_icon.size = sizeof(RemoteNTDLLPatchIcon);
	remotentdllunpatch_menu_icon.data = RemoteNTDLLUnpatchIcon;
	remotentdllunpatch_menu_icon.size = sizeof(RemoteNTDLLUnpatchIcon);
	
	openlogs_menu_icon.data = OpenLogsIcon;
	openlogs_menu_icon.size = sizeof(OpenLogsIcon);
	clearlogs_menu_icon.data = ClearLogsIcon;
	clearlogs_menu_icon.size = sizeof(ClearLogsIcon);
	
    helpicon_menu_icon.data = HelpIcon;
    helpicon_menu_icon.size = sizeof(HelpIcon);

	
    // Add menu item entries
    _plugin_menuaddentry(hMenu, MENU_HOOK, "&Hook process creation");
    _plugin_menuaddentry(hMenu, MENU_AUTO_HOOK, "&Auto from " ARCH_TXT "dbg Hook process creation");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_CLEAR, "&Clear " ARCH_TXT "\\CPIDS");
    _plugin_menuaddentry(hMenu, MENU_OPENCPIDS, "&Open " ARCH_TXT "\\CPIDS");
    _plugin_menuaddentry(hMenu, MENU_CREATE_CPID, "&Create new entry " ARCH_TXT "\\CPIDS");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_UNPATCH_NTDLL, "&Unpatch NTDLL entry");
    _plugin_menuaddentry(hMenu, MENU_PATCH_NTDLL, "&Patch NTDLL entry");
    _plugin_menuaddentry(hMenu, MENU_AUTO_UNPATCH_NTDLL, "&Auto from " ARCH_TXT "dbg Unpatch NTDLL entry");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_NEW_PROCESS_WATCHER, "&Launch NewProcessWatcher");
    _plugin_menuaddentry(hMenu, MENU_NEW_PROCESS_WATCHER_OLD, "&Launch NewProcessWatcher with old processes");
    _plugin_menuaddentry(hMenu, MENU_NEW_PROCESS_WATCHER_NO_ASK, "&Launch from " ARCH_TXT "dbg NewProcessWatcher without ask");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_GO_TO_HOOK, "&Go to Hook process creation");
    _plugin_menuaddentry(hMenu, MENU_GO_TO_NTDLL, "&Go to NTDLL patch");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_EDIT_PRE, "&Edit " ARCH_TXT " suspended command");
    _plugin_menuaddentry(hMenu, MENU_EDIT_POST, "&Edit " ARCH_TXT " resumed command");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_REMOTE_HOOK, "&Remote " ARCH_TXT " PID Hook process creation");
    _plugin_menuaddentry(hMenu, MENU_REMOTE_NTDLL_PATCH, "&Remote " ARCH_TXT " PID Patch NTDLL entry");
    _plugin_menuaddentry(hMenu, MENU_REMOTE_NTDLL_UNPATCH, "&Remote " ARCH_TXT " PID Unpatch NTDLL entry");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_OPENLOGS, "&Open logs");
    _plugin_menuaddentry(hMenu, MENU_CLEARLOGS, "&Clear logs");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_HELP, "&Help");
    _plugin_menuaddseparator(hMenu);

    _plugin_menuaddentry(hMenu, MENU_INFO, "&Plugin info by Dreg");

	
    // Add icons to menu item entries
    _plugin_menuseticon(hMenu, &dbgchild_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_HOOK, &hookprocess_menu_icon);
	
    _plugin_menuentryseticon(pluginHandle, MENU_CLEAR, &clearcpids_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_OPENCPIDS, &browsecpids_menu_icon);
	_plugin_menuentryseticon(pluginHandle, MENU_CREATE_CPID, &addcpids_menu_icon);
	
    _plugin_menuentryseticon(pluginHandle, MENU_UNPATCH_NTDLL, &unpatchntdll_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_PATCH_NTDLL, &patchntdll_menu_icon);
	
    _plugin_menuentryseticon(pluginHandle, MENU_NEW_PROCESS_WATCHER, &newprocesswatcher_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_NEW_PROCESS_WATCHER_OLD, &newprocesswatcher_menu_icon);
	
    _plugin_menuentryseticon(pluginHandle, MENU_GO_TO_HOOK, &gotohook_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_GO_TO_NTDLL, &gotontdll_menu_icon);
	
    _plugin_menuentryseticon(pluginHandle, MENU_EDIT_PRE, &editsuspendedicon_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_EDIT_POST, &editresumedicon_menu_icon);
	
	_plugin_menuentryseticon(pluginHandle, MENU_REMOTE_HOOK, &remoteprocesshook_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_REMOTE_NTDLL_PATCH, &remotentdllpatch_menu_icon);
    _plugin_menuentryseticon(pluginHandle, MENU_REMOTE_NTDLL_UNPATCH, &remotentdllunpatch_menu_icon);
	
	_plugin_menuentryseticon(pluginHandle, MENU_OPENLOGS, &openlogs_menu_icon);
	_plugin_menuentryseticon(pluginHandle, MENU_CLEARLOGS, &clearlogs_menu_icon);
	
    _plugin_menuentryseticon(pluginHandle, MENU_HELP, &helpicon_menu_icon);
	
    _plugin_menuentryseticon(pluginHandle, MENU_INFO, &dbgchild_menu_icon);

	
    hwndDlg = GuiGetWindowHandle();

    char rd_value[MAX_PATH];
    bool auto_enable = true;

    ZeroMemory(rd_value, sizeof(rd_value));
    if (BridgeSettingGet("dbgchild", "auto_unpatch_ntdll", rd_value) == false)
    {
        BridgeSettingSet("dbgchild", "auto_unpatch_ntdll", "true");
        BridgeSettingFlush();
    }
    if (BridgeSettingGet("dbgchild", "auto_unpatch_ntdll", rd_value))
    {
        if (strcmp(rd_value, "true") == 0)
        {
            auto_enable = true;
        }
        else
        {
            auto_enable = false;
        }
    }
    _plugin_menuentrysetchecked(pluginHandle, MENU_AUTO_UNPATCH_NTDLL, auto_enable);

    ZeroMemory(rd_value, sizeof(rd_value));
    auto_enable = false;
    if (BridgeSettingGet("dbgchild", "auto_hook", rd_value) == false)
    {
        BridgeSettingSet("dbgchild", "auto_hook", "false");
        BridgeSettingFlush();
    }
    if (BridgeSettingGet("dbgchild", "auto_hook", rd_value))
    {
        if (strcmp(rd_value, "true") == 0)
        {
            auto_enable = true;
        }
        else
        {
            auto_enable = false;
        }
    }
    _plugin_menuentrysetchecked(pluginHandle, MENU_AUTO_HOOK, auto_enable);

    ZeroMemory(rd_value, sizeof(rd_value));
    auto_enable = false;
    if (BridgeSettingGet("dbgchild", "watcher_no_ask", rd_value) == false)
    {
        BridgeSettingSet("dbgchild", "watcher_no_ask", "false");
        BridgeSettingFlush();
    }
    if (BridgeSettingGet("dbgchild", "watcher_no_ask", rd_value))
    {
        if (strcmp(rd_value, "true") == 0)
        {
            auto_enable = true;
        }
        else
        {
            auto_enable = false;
        }
    }
    _plugin_menuentrysetchecked(pluginHandle, MENU_NEW_PROCESS_WATCHER_NO_ASK, auto_enable);

}


