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
    printf("\n"
        "DbgChild - Create Process Patch\n"
        "-\n"
        "MIT License\n"
        "-\n"
        "Copyright (c) <2017> <David Reguera Garcia aka Dreg>\n"
        "http://www.fr33project.org/\n"
        "https://github.com/David-Reguera-Garcia-Dreg\n"
        "dreg@fr33project.org\n"
        "- \n"
        "CreateProcessPatch Version: "
    );

    EnableDebugPrivilege();

#ifdef _WIN64
    puts("x64");
#else
    puts("x86");
#endif

    puts("-\n");

    CreateProcessPatch(5124);
    if (argc > 1)
    {
        DWORD pid = atoi(argv[1]);
        CreateProcessPatch(pid);
    }
    else
    {
        fprintf(stderr, "Syntax Error, Usage: program.exe PID_DECIMAL\n");
    }

    puts("\nPress ENTER to exit.");
    getchar();

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

    printf("PID: %" PRIu64 " , Handle: %" PRIu64 "\n", (uint64_t)pid, (uint64_t)hProcess);

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

        puts(
            "Process Openned!\n"
            "Assuming the local NTDLL its equal to remote NTDLL (for disas etc)"
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
                "CreateProcessPatch_x32 for x32 processes.\n"
                "CreateProcessPatch_x64 for x64 processes.\n"
            );
            CloseHandle(hProcess);
            return;
        }

        printf(
            "NTDLL: 0x%" PRIXPTR "\n"
            "NTDLL DOS STUB PATCH (only x64): 0x%" PRIXPTR "\n"
            "ZwCreateUserProcess: 0x%" PRIXPTR "\n"
            "LdrLoadDll: 0x%" PRIXPTR "\n"
            "LdrGetProcedureAddress: 0x%" PRIXPTR "\n"
            "RtlDosPathNameToRelativeNtPathName_U: 0x%" PRIXPTR "\n",
            (uintptr_t)ntdll_base,
            (uintptr_t)ntdll_dos_stub,
            (uintptr_t)ZwCreateUserProcess_f,
            (uintptr_t)LdrLoadDll_f,
            (uintptr_t)LdrGetProcedureAddress_f,
            (uintptr_t)RtlDosPathNameToRelativeNtPathName_U_f);

        printf("Local Payload EP: 0x%" PRIXPTR " , Payload Size 0x%X\n",
            (uintptr_t)payload_ep,
            payload_size);

        payload = VirtualAllocEx(
            hProcess,
            NULL,
            payload_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        printf("Remote Process Payload EP: 0x%" PRIXPTR "\n", (uintptr_t)payload);

        printf("Dis Base Address: 0x%" PRIXPTR " , bytes to replaced: %d , max_bytes %d\n",
            (uintptr_t)ZwCreateUserProcess_f,
            (int)size_pushret,
            (int)0x40);

        size_t total_bytes = GetBytesInstructionsReplaced(
            ((unsigned char*)ZwCreateUserProcess_f),
            size_pushret,
            0x40);

        printf("Total instructions bytes to replace %d\n", (int)total_bytes);

        zwcreateuserprocess_next_valid_instruction =
            ((unsigned char*)ZwCreateUserProcess_f)
            +
            total_bytes;

        printf("Next valid instruction after the hook: 0x%" PRIXPTR "\n", (uintptr_t)zwcreateuserprocess_next_valid_instruction);
        GetBytesInstructionsReplaced(
            zwcreateuserprocess_next_valid_instruction,
            0x10,
            0x10);

        trampoline_ptr = (unsigned char*)trampoline;
        memcpy(trampoline_ptr, ((unsigned char*)ZwCreateUserProcess_f), total_bytes);
        trampoline_ptr += total_bytes;

        printf("Checking Dangerous Instruction in trampoline...\n");
        CheckDangerousInstructions(ZwCreateUserProcess_f, total_bytes);

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

        puts("Trampoline created:");
        GetBytesInstructionsReplaced(
            trampoline,
            sizeof(trampoline),
            sizeof(trampoline)
        );

        FillPayload((unsigned char*)payload, trampoline, trampoline_ptr - trampoline,
            NULL);

        PatchCode(hProcess, payload, payload_ep, payload_size, NULL, 0, NULL, 0);
        puts("Written remote payload!");

#ifdef _WIN64
        PatchCode(hProcess, ntdll_dos_stub, &payload, sizeof(payload), NULL, 0, NULL, 0);
        puts("Written absolute address to payload in remote NTDLL DOS STUB!");

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
        puts("PUSH [NTDLL DOS STUB] + RET written in remote ZwCreateUserProcess EP");
#else
        puts("PUSH + RET written in remote ZwCreateUserProcess EP");
#endif

        puts("Remote instructions before the patch:");
        total_bytes = GetBytesInstructionsReplaced(code_before_patch, total_bytes, sizeof(code_before_patch));
        CheckDangerousInstructions(code_before_patch, total_bytes);
        
        puts("Remote instructions after the patch:");
        GetBytesInstructionsReplaced(code_after_patch, total_bytes, sizeof(code_after_patch));

        CloseHandle(hProcess);
    }
    else
    {
        fprintf(stderr, "Error Openning Process.\n");
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
    DWORD dwAttrib = 0;
    WCHAR cpids_full_path[MAX_PATH] = { 0 };

    if (!MakePayloadPagesFullRights(payload_ep, payload_size))
    {
        fprintf(stderr, "Error Make Local Payload Memory with Full Rights\n");
        return;
    }

    puts("Changed Local Payload Memory with Full Rights");

    if (dll_work_full_path == NULL)
    {
        GetCurrentPath(current_path);
        dll_work_full_path = current_path;
    }
    wprintf(L"Own DLL dir work path: %s\n", dll_work_full_path);

    wcscpy_s(own_dll_path, dll_work_full_path);
    wcscpy_s(cpids_full_path, own_dll_path);
    wcscat_s(own_dll_path, OWN_DLL_NAME_W);

    RtlDosPathNameToRelativeNtPathName_U_f(dll_work_full_path, &NtFileName, NULL,
        NULL);

    memcpy(payload_dll_work_full_path, NtFileName.Buffer,
        (NtFileName.Length > MAX_PATH) ? MAX_PATH : NtFileName.Length);

    wprintf(L"Own DLL dir work path to NT path: %s\n", payload_dll_work_full_path);

    memcpy(get_trampoline(), trampoline, trampoline_size);

    *payload_ldr_load_dll_sym = (void*)LdrLoadDll_f;
    *payload_get_procedure_address = (void*)LdrGetProcedureAddress_f;

    memcpy(payload_dll_func_name, API_NAME_A, sizeof(API_NAME_A));
    payload_dll_ansi_string->Buffer = (PCHAR)(remote_payload + (((unsigned char*)
        payload_dll_func_name) - ((unsigned char*)payload_ep)));
    payload_dll_ansi_string->MaximumLength = sizeof(API_NAME_A);
    payload_dll_ansi_string->Length = sizeof(API_NAME_A) - 1;

    printf("Own DLL API name export: %s\n", (char*)payload_dll_func_name);

    own_dll_path_size = (DWORD)(wcslen(own_dll_path) * sizeof(wchar_t));
    memcpy(payload_dll_str, own_dll_path, own_dll_path_size);
    payload_dll_unicode_str->Buffer = PWSTR(remote_payload + (((unsigned char*)
        payload_dll_str) - ((unsigned char*)payload_ep)));
    payload_dll_unicode_str->MaximumLength = (USHORT)(own_dll_path_size + 2);
    payload_dll_unicode_str->Length = (USHORT)own_dll_path_size;

    wprintf(L"Own DLL full path: %s\n", payload_dll_str);

    dwAttrib = GetFileAttributesW(payload_dll_str);
    if ((dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)))
    {
        puts("OK - Own DLL full path exist");
    }
    else
    {
        fprintf(stderr, "WARNING - Own DLL full path NO EXIST!\n");
    }

    wcscat_s(cpids_full_path, L"CPIDS");
    wprintf(L"Checking CPIDS path: %s\n", cpids_full_path);
    if (DirExistW(cpids_full_path))
    {
        puts("OK - CPIDS path exist");
    }
    else
    {
        fprintf(stderr, "WARNING - CPIDS path NO EXIST!\n");
    }
}

BOOL MakePayloadPagesFullRights(void* payload_address, size_t size)
{
    DWORD old_protect;
    DWORD total_pages = PAGE_ROUND_UP(((unsigned char*)payload_address) + size)
        - PAGE_ROUND_DOWN(payload_address);

    return VirtualProtect(
        (LPVOID)PAGE_ROUND_DOWN(payload_address),
        total_pages,
        PAGE_EXECUTE_READWRITE,
        &old_protect);
}

