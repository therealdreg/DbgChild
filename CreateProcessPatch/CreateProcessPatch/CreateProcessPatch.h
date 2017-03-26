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

#ifndef _CREATE_PROCESS_PATCH_H__
#define _CREATE_PROCESS_PATCH_H__

#include <windows.h>
#include "capstone.h"

#define PAGE_SIZE 4096
#define PAGE_ROUND_DOWN(x) (((ULONG_PTR)(x)) & (~(PAGE_SIZE-1)))
#define PAGE_ROUND_UP(x) ( (((ULONG_PTR)(x)) + PAGE_SIZE-1)  & (~(PAGE_SIZE-1)) )
#define DISTANCE_TO_NEW_EP_ZwCreateUserProcess (0x10)
#define API_NAME_A ("ZwCreateUserProcess")
#define OWN_DLL_NAME_W (L"DbgChildHookDLL.dll")

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _RTL_RELATIVE_NAME
{
    UNICODE_STRING RelativeName;
    HANDLE         ContainingDirectory;
    void*          CurDirRef;
} RTL_RELATIVE_NAME, *PRTL_RELATIVE_NAME;


typedef BOOLEAN(NTAPI* RtlDosPathNameToRelativeNtPathName_U_t)(
    _In_       PCWSTR DosFileName,
    _Out_      PUNICODE_STRING NtFileName,
    _Out_opt_  PWSTR* FilePath,
    _Out_opt_  PRTL_RELATIVE_NAME RelativeName
    );

typedef NTSTATUS(NTAPI* LdrLoadDll_t)(
    IN PWSTR SearchPath OPTIONAL,
    IN PULONG LoadFlags OPTIONAL,
    IN PUNICODE_STRING Name,
    OUT PVOID* BaseAddress OPTIONAL
    );

typedef NTSTATUS(NTAPI* LdrGetProcedureAddress_t)(
    IN PVOID              ModuleHandle,
    IN PANSI_STRING         FunctionName OPTIONAL,
    IN WORD                 Oridinal OPTIONAL,
    OUT PVOID*               FunctionAddress
    );

typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

typedef void (WINAPI* GetNativeSystemInfo_t)(
    _Out_ LPSYSTEM_INFO lpSystemInfo
    );

extern LPFN_ISWOW64PROCESS fnIsWow64Process;
extern GetNativeSystemInfo_t GetNativeSystemInfo_f;
extern LdrLoadDll_t LdrLoadDll_f;
extern LdrGetProcedureAddress_t LdrGetProcedureAddress_f;
extern RtlDosPathNameToRelativeNtPathName_U_t RtlDosPathNameToRelativeNtPathName_U_f;
extern void* ZwCreateUserProcess_f;

BOOL Is64BitProcess(HANDLE process);
BOOL DirExistW(WCHAR* dirName);
int TestLdrLoadDllLdrGetProcedureAddress();
void TestPayloadInMyMemory();
void CreateProcessPatch(DWORD pid);
void FillPayload(unsigned char* remote_payload,
    void* trampoline,
    size_t trampoline_size,
    WCHAR* dll_work_full_path);
size_t GetBytesInstructionsReplaced(void* address,
    size_t bytes_to_replaced,
    size_t max_bytes);
BOOL MakePayloadPagesFullRights(void* payload_address, size_t size);
BOOL PatchCode(HANDLE process,
    void* address,
    void* code,
    SIZE_T code_size,
    void* original_code);

extern "C" void hello_world_asm();
extern "C" DWORD get_payload_size();
extern "C" VOID* get_payload_ep();
extern "C" VOID* get_payload_dll_str();
extern "C" VOID* get_payload_dll_unicode_str();
extern "C" VOID** get_payload_ldr_load_dll_sym();
extern "C" VOID** get_payload_get_procedure_address();
extern "C" VOID* get_payload_dll_func_name();
extern "C" VOID* get_payload_dll_ansi_string();
extern "C" VOID* get_trampoline();
extern "C" WCHAR* get_dll_work_full_path();

#endif /* _CREATE_PROCESS_PATCH_H__ */