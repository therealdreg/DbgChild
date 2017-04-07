/*
DbgChild - Create Process Patch
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
#include "CreateProcessPatch.h"

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

LdrLoadDll_t LdrLoadDll_f = (LdrLoadDll_t)GetProcAddress(GetModuleHandleW(
    L"ntdll.dll"),
    "LdrLoadDll");

LdrGetProcedureAddress_t LdrGetProcedureAddress_f = (LdrGetProcedureAddress_t)
GetProcAddress(GetModuleHandleW(
    L"ntdll.dll"),
    "LdrGetProcedureAddress");

RtlDosPathNameToRelativeNtPathName_U_t RtlDosPathNameToRelativeNtPathName_U_f =
(RtlDosPathNameToRelativeNtPathName_U_t)
GetProcAddress(
    GetModuleHandleW(L"ntdll.dll"),
    "RtlDosPathNameToRelativeNtPathName_U");

void* ZwCreateUserProcess_f = (void*)GetProcAddress(
    GetModuleHandleW(L"ntdll.dll"),
    "ZwCreateUserProcess");

int main(int argc, char* argv[])
{
    my_log = InitLog(L"CreateProcessPatch");

    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"\r\n"
        L"DbgChild - Create Process Patch\r\n"
        L"-\r\n"
        L"MIT License\r\n"
        L"-\r\n"
        L"Copyright (c) <2017> <David Reguera Garcia aka Dreg>\r\n"
        L"http://www.fr33project.org/\r\n"
        L"https://github.com/David-Reguera-Garcia-Dreg\r\n"
        L"dreg@fr33project.org\r\n"
        L"-\r\n"
        L"CreateProcessPatch Version: %s\r\n\r\n"
        ,
#ifdef _WIN64
        L"x64"
#else
        L"x86"
#endif
    );

    EnableDebugPrivilege();

    if (argc > 1)
    {
        DWORD pid = atoi(argv[1]);
        CreateProcessPatch(pid);
    }
    else
    {
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            "Syntax Error, Usage: program.exe PID_DECIMAL\r\n"
        );
    }

    CloseLog(my_log);

    return 0;
}

int TestLdrLoadDllLdrGetProcedureAddress()
{
#define FULL_DLL_PATHW (L"C:\\Users\\Dreg\\DbgChild\\CreateProcessPatch\\x64\\Debug\\DbgChildHookDLL.dll")
    PWSTR null_search_path = NULL;
    ULONG null_load_flags = 0;
    UNICODE_STRING dll_full_path =
    {
        sizeof(FULL_DLL_PATHW) - 2,
        sizeof(FULL_DLL_PATHW),
        FULL_DLL_PATHW
    };
    ANSI_STRING api_name =
    {
        sizeof(API_NAME_A) - 1,
        sizeof(API_NAME_A),
        API_NAME_A
    };
    VOID* base_address = NULL;
    VOID* api_address = NULL;

    LdrLoadDll_f((PWSTR)&null_search_path, &null_load_flags, &dll_full_path,
        &base_address);

    LoadLibraryExW(FULL_DLL_PATHW, NULL, 0);

    printf("Base Address: 0x%" PRIXPTR " vs 0x%" PRIXPTR "\n", (uintptr_t)base_address,
        (uintptr_t)GetModuleHandleW(FULL_DLL_PATHW));

    LdrGetProcedureAddress_f(base_address, &api_name, 0, &api_address);

    printf("API Address : 0x%" PRIXPTR " vs 0x%" PRIXPTR "\n", (uintptr_t)api_address,
        (uintptr_t)GetProcAddress(GetModuleHandleW(FULL_DLL_PATHW), API_NAME_A));

    return 0;
}

void TestPayloadInMyMemory()
{
    DWORD payload_size = get_payload_size();
    void* payload_ep = get_payload_ep();
    VOID* payload_relocated = VirtualAlloc(NULL, payload_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    FillPayload((unsigned char*)payload_relocated, "\xCC", 1, NULL);

    memcpy(payload_relocated, payload_ep, payload_size);

    ZeroMemory(payload_ep, payload_size);

    ((void(*)(void))payload_relocated)();
}

void CreateProcessPatch(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION, FALSE, pid);

    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO "PID: %" PRIu64 " , Handle: %" PRIu64 "\r\n", (uint64_t)pid, (uint64_t)hProcess);

    if (hProcess)
    {
        unsigned char* ntdll_base = (unsigned char*)GetModuleHandleW(L"ntdll.dll");
        unsigned char* ntdll_dos_stub = (ntdll_base + sizeof(IMAGE_DOS_HEADER)) +
            DISTANCE_TO_NEW_EP_ZwCreateUserProcess;
#ifdef _WIN64
        unsigned char pushret_relative_ref[] = { 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0xC3,
            0x90, 0x90, 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90,
            0x90, 0x90, 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90
        };
        DWORD* jmp_dest = (DWORD*)&pushret_relative_ref[2];
#else
        unsigned char pushret_relative_ref[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3, 
            0x90, 0x90, 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90,
            0x90, 0x90, 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90 , 0x90
        };
#endif
        LPVOID payload = NULL;
        unsigned char* zwcreateuserprocess_next_valid_instruction = NULL;
        unsigned char trampoline[40] = { 0x90 };
        unsigned char* trampoline_ptr = NULL;
        DWORD payload_size = get_payload_size();
        void* payload_ep = get_payload_ep();
        BOOL is_64_proc = Is64BitProcess(hProcess);
        unsigned char code_before_patch[0x40] = { 0 };
        unsigned char code_after_patch[0x40] = { 0 };
#ifdef _WIN64   
        DWORD size_pushret = 7;
#else
        DWORD size_pushret = 6;
#endif

        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"Process Openned!\r\n"
            L"Assuming the local NTDLL its equal to remote NTDLL (for disas etc)\r\n"
        );

        wchar_t* is_proc_str = NULL;
        if (is_64_proc)
        {
            is_proc_str = L"x64";
        }
        else
        {
            is_proc_str = L"x32";
        }

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Remote process is: %s\r\n"
            ,
            is_proc_str
        );

        if (is_64_proc != Is64BitProcess(GetCurrentProcess()))
        {
            LogW(
                my_log,
                TRUE, 
                LOG_TAG_ERROR
                L"Error, you must use:\r\n"
                L"CreateProcessPatch_x32 for x32 processes.\r\n"
                L"CreateProcessPatch_x64 for x64 processes.\r\n"
            );
            CloseHandle(hProcess);
            return;
        }

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"NTDLL: 0x%" PRIXPTR "\r\n"
            L"NTDLL DOS STUB PATCH (only x64): 0x%" PRIXPTR "\r\n"
            L"ZwCreateUserProcess: 0x%" PRIXPTR "\r\n"
            L"LdrLoadDll: 0x%" PRIXPTR "\r\n"
            L"LdrGetProcedureAddress: 0x%" PRIXPTR "\r\n"
            L"RtlDosPathNameToRelativeNtPathName_U: 0x%" PRIXPTR "\r\n",
            (uintptr_t)ntdll_base,
            (uintptr_t)ntdll_dos_stub,
            (uintptr_t)ZwCreateUserProcess_f,
            (uintptr_t)LdrLoadDll_f,
            (uintptr_t)LdrGetProcedureAddress_f,
            (uintptr_t)RtlDosPathNameToRelativeNtPathName_U_f);

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Local Payload EP: 0x%" PRIXPTR " , Payload Size 0x%X\r\n",
            (uintptr_t)payload_ep,
            payload_size);

        payload = VirtualAllocEx(
            hProcess,
            NULL,
            payload_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Remote Process Payload EP: 0x%" PRIXPTR "\r\n", (uintptr_t)payload);

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Dis Base Address: 0x%" PRIXPTR " , bytes to replaced: %d , max_bytes %d\r\n",
            (uintptr_t)ZwCreateUserProcess_f,
            (int)size_pushret,
            (int)0x40);

        size_t total_bytes = GetBytesInstructionsReplaced(
            ((unsigned char*)ZwCreateUserProcess_f),
            ((unsigned char*)ZwCreateUserProcess_f),
            size_pushret,
            0x40);

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Total instructions bytes to replace %d\r\n", (int)total_bytes);

        zwcreateuserprocess_next_valid_instruction =
            ((unsigned char*)ZwCreateUserProcess_f)
            +
            total_bytes;

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Next valid instruction after the hook: 0x%" PRIXPTR "\r\n", (uintptr_t)zwcreateuserprocess_next_valid_instruction);
        GetBytesInstructionsReplaced(
            zwcreateuserprocess_next_valid_instruction,
            zwcreateuserprocess_next_valid_instruction,
            0x10,
            0x10);

        trampoline_ptr = (unsigned char*)trampoline;
        memcpy(trampoline_ptr, ((unsigned char*)ZwCreateUserProcess_f), total_bytes);
        trampoline_ptr += total_bytes;

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Checking Dangerous Instruction in trampoline...\r\n");
        CheckDangerousInstructions(ZwCreateUserProcess_f, ZwCreateUserProcess_f, total_bytes);

#ifdef _WIN64
        pushret_relative_ref[2] = 0x01;
#else 
        memcpy(&(pushret_relative_ref[1]), &zwcreateuserprocess_next_valid_instruction,
            sizeof(zwcreateuserprocess_next_valid_instruction));
#endif
        memcpy(trampoline_ptr, pushret_relative_ref, size_pushret);
        trampoline_ptr += size_pushret;
#ifdef _WIN64
        memcpy(trampoline_ptr, &zwcreateuserprocess_next_valid_instruction,
            sizeof(zwcreateuserprocess_next_valid_instruction));
        trampoline_ptr += sizeof(zwcreateuserprocess_next_valid_instruction);
#endif

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Trampoline created:\r\n");
        GetBytesInstructionsReplaced(
            trampoline,
            trampoline,
            sizeof(trampoline),
            sizeof(trampoline)
        );

        FillPayload((unsigned char*)payload, trampoline, trampoline_ptr - trampoline,
            NULL);

        PatchCode(hProcess, payload, payload_ep, payload_size, NULL, 0, NULL, 0);
        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"Written remote payload!\r\n");

#ifdef _WIN64
        PatchCode(hProcess, ntdll_dos_stub, &payload, sizeof(payload), NULL, 0, NULL, 0);
        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"Written absolute address to payload in remote NTDLL DOS STUB!\r\n");

        *jmp_dest = (DWORD)(ntdll_dos_stub - (((unsigned char*)ZwCreateUserProcess_f) +
            (size_pushret - 1)));
#else
        memcpy(&(pushret_relative_ref[1]), &payload, sizeof(payload));
#endif
        PatchCode(
            hProcess, 
            ((unsigned char*)ZwCreateUserProcess_f), 
            pushret_relative_ref,
            total_bytes,
            code_before_patch,
            sizeof(code_before_patch),
            code_after_patch,
            sizeof(code_after_patch)
        );

#ifdef _WIN64
        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"PUSH [NTDLL DOS STUB] + RET written in remote ZwCreateUserProcess EP\r\n");
#else
        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"PUSH + RET written in remote ZwCreateUserProcess EP\r\n");
#endif

        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Remote instructions before the patch:\r\n");
        total_bytes = GetBytesInstructionsReplaced(code_before_patch, ZwCreateUserProcess_f, total_bytes, sizeof(code_before_patch));
        CheckDangerousInstructions(code_before_patch, ZwCreateUserProcess_f, total_bytes);
        
        LogW(
            my_log,
            FALSE,
            LOG_TAG_INFO
            L"Remote instructions after the patch:\r\n");
        GetBytesInstructionsReplaced(code_after_patch, ZwCreateUserProcess_f, total_bytes, sizeof(code_after_patch));

        CloseHandle(hProcess);
    }
    else
    {
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            L"Error Openning Process.\r\n");
    }
}

void FillPayload(
    unsigned char* remote_payload,
    void* trampoline,
    size_t trampoline_size,
    WCHAR* dll_work_full_path)
{
    void* payload_ep = get_payload_ep();
    size_t payload_size = get_payload_size();
    PUNICODE_STRING payload_dll_unicode_str = (PUNICODE_STRING)get_payload_dll_unicode_str();
    PWSTR payload_dll_str = (PWSTR)get_payload_dll_str();
    void** payload_ldr_load_dll_sym = get_payload_ldr_load_dll_sym();
    void** payload_get_procedure_address = get_payload_get_procedure_address();
    void* payload_dll_func_name = get_payload_dll_func_name();
    PANSI_STRING payload_dll_ansi_string = (PANSI_STRING)get_payload_dll_ansi_string();
    WCHAR* payload_dll_work_full_path = get_dll_work_full_path();
    WCHAR current_path[MAX_PATH] = { 0 };
    WCHAR* tmp_ptr = NULL;
    UNICODE_STRING NtFileName = { 0 };
    WCHAR own_dll_path[MAX_PATH] = { 0 };
    DWORD own_dll_path_size = 0;
    WCHAR cpids_full_path[MAX_PATH] = { 0 };

    if (!MakePayloadPagesFullRights(payload_ep, payload_size))
    {
        LogW(
            my_log,
            TRUE,
            LOG_TAG_ERROR
            L"Error Make Local Payload Memory with Full Rights\r\n");
        return;
    }

    LogW(
        my_log,
        FALSE,
        LOG_TAG_OK
        L"Changed Local Payload Memory with Full Rights\r\n");

    if (dll_work_full_path == NULL)
    {
        GetCurrentPath(current_path);
        dll_work_full_path = current_path;
    }
    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"Own DLL dir work path: %s\r\n", dll_work_full_path);

    wcscpy_s(own_dll_path, dll_work_full_path);
    wcscpy_s(cpids_full_path, own_dll_path);
    wcscat_s(own_dll_path, OWN_DLL_NAME_W);

    RtlDosPathNameToRelativeNtPathName_U_f(dll_work_full_path, &NtFileName, NULL,
        NULL);

    memcpy(payload_dll_work_full_path, NtFileName.Buffer,
        (NtFileName.Length > MAX_PATH) ? MAX_PATH : NtFileName.Length);

    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"Own DLL dir work path to NT path: %s\r\n", payload_dll_work_full_path);

    memcpy(get_trampoline(), trampoline, trampoline_size);

    *payload_ldr_load_dll_sym = (void*)LdrLoadDll_f;
    *payload_get_procedure_address = (void*)LdrGetProcedureAddress_f;

    memcpy(payload_dll_func_name, API_NAME_A, sizeof(API_NAME_A));
    payload_dll_ansi_string->Buffer = (PCHAR)(remote_payload + (((unsigned char*)
        payload_dll_func_name) - ((unsigned char*)payload_ep)));
    payload_dll_ansi_string->MaximumLength = sizeof(API_NAME_A);
    payload_dll_ansi_string->Length = sizeof(API_NAME_A) - 1;

    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"Own DLL API name export: %S\r\n", (char*)payload_dll_func_name);

    own_dll_path_size = (DWORD)(wcslen(own_dll_path) * sizeof(wchar_t));
    memcpy(payload_dll_str, own_dll_path, own_dll_path_size);
    payload_dll_unicode_str->Buffer = PWSTR(remote_payload + (((unsigned char*)
        payload_dll_str) - ((unsigned char*)payload_ep)));
    payload_dll_unicode_str->MaximumLength = (USHORT)(own_dll_path_size + 2);
    payload_dll_unicode_str->Length = (USHORT)own_dll_path_size;

    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"Own DLL full path: %s\r\n", payload_dll_str);

    if (FileExistW(payload_dll_str))
    {
        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"OK - Own DLL full path exist\r\n");
    }
    else
    {
        LogW(
            my_log,
            FALSE,
            LOG_TAG_WARNING
            L"WARNING - Own DLL full path NO EXIST!\r\n");
    }

    wcscat_s(cpids_full_path, L"CPIDS");
    LogW(
        my_log,
        FALSE,
        LOG_TAG_INFO
        L"Checking CPIDS path: %s\r\n", cpids_full_path);
    if (DirExistW(cpids_full_path))
    {
        LogW(
            my_log,
            FALSE,
            LOG_TAG_OK
            L"OK - CPIDS path exist\r\n");
    }
    else
    {
        LogW(
            my_log,
            FALSE,
            LOG_TAG_WARNING
            L"WARNING - CPIDS path NO EXIST!\r\n");
    }
}

BOOL MakePayloadPagesFullRights(void* payload_address, size_t size)
{
    DWORD old_protect = 0;
    DWORD total_pages_bytes = (PAGE_ROUND_UP(((unsigned char*)payload_address) + (size - 1)) - PAGE_ROUND_DOWN(payload_address));

    return VirtualProtect(
        (LPVOID)PAGE_ROUND_DOWN(payload_address),
        total_pages_bytes,
        PAGE_EXECUTE_READWRITE,
        &old_protect);
}

