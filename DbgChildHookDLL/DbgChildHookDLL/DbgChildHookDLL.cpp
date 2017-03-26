/*
DbgChild - Hook DLL
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
#include "DbgChildHookDLL.h"


/*
TODO:
Refactorize
check memory operations & paths bounds etc
fix possibles buffers overflows, underruns etc.
Documentation
Consistent Variable Names
....
*/

ZwCreateUserProcess_t ZwCreateUserProcess_f = NULL;

WCHAR* work_path = NULL;

NtDelayExecution_t NtDelayExecution_f = (NtDelayExecution_t)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");

NtCreateFile_t NtCreateFile_f = (NtCreateFile_t)GetProcAddress(
                                    GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");

ZwClose_t ZwClose_f = (ZwClose_t)GetProcAddress(
                          GetModuleHandleW(L"ntdll.dll"), "ZwClose");

NtReadFile_t NtReadFile_f = (NtReadFile_t)GetProcAddress(
                                GetModuleHandleW(L"ntdll.dll"), "NtReadFile");

NtQueryInformationProcess_t NtQueryInformationProcess_f =
    (NtQueryInformationProcess_t)
    GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

RtlInitUnicodeString_t RtlInitUnicodeString_f = (RtlInitUnicodeString_t)
        GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");

DBGCHILDHOOKDLL_API NTSTATUS WINAPI ZwCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__"=" __FUNCDNAME__)
    ZwCreateUserProcess_f = (ZwCreateUserProcess_t)
                            ((void* (*)(void))GetCax)();

    work_path = (WCHAR*)(((unsigned char*)ZwCreateUserProcess_f) + 80);

    return _ZwCreateUserProcess(ProcessHandle,
                                ThreadHandle,
                                ProcessDesiredAccess,
                                ThreadDesiredAccess,
                                ProcessObjectAttributes,
                                ThreadObjectAttributes,
                                ProcessFlags,
                                ThreadFlags,
                                ProcessParameters,
                                CreateInfo,
                                AttributeList);
}

NTSTATUS WINAPI _ZwCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList)
{
    NTSTATUS retf = ZwCreateUserProcess_f(ProcessHandle,
                                          ThreadHandle,
                                          ProcessDesiredAccess,
                                          ThreadDesiredAccess,
                                          ProcessObjectAttributes,
                                          ThreadObjectAttributes,
                                          ProcessFlags,
                                          ThreadFlags,
                                          ProcessParameters,
                                          CreateInfo,
                                          AttributeList);

    if (NT_SUCCESS(retf))
    {
        HANDLE hFile = 0;
        OBJECT_ATTRIBUTES objAttribs = { 0 };
        UNICODE_STRING unicodeString = { 0 };
        char file_name_path[] = { '\\', 'C', 'P', 'I', 'D', 'S', '\\',
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                                };
        wchar_t file_name_pathw[sizeof(file_name_path) * 2] = { 0 };
        unsigned char* ptr_file_name_pathw = (unsigned char*)file_name_pathw;
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        size_t size_str = 0;
        wchar_t my_actual_path[MAX_PATH] = { 0 };
        LARGE_INTEGER largeInteger = { 0 };
        IO_STATUS_BLOCK ioStatusBlock = { 0 };

        // TODO: check the return..
        NtQueryInformationProcess_f(*ProcessHandle,
                                    ProcessBasicInformation,
                                    &pbi,
                                    sizeof(pbi),
                                    NULL);

        size_str = MyItoa((DWORD)pbi.UniqueProcessId, file_name_path + 7, 10);

        for (int i = 0; i < size_str + 7; i++)
        {
            *ptr_file_name_pathw = file_name_path[i];
            ptr_file_name_pathw += 2;
        }

        MyMemcpy(my_actual_path, work_path, MyWStrlen(work_path) * sizeof(wchar_t));

        MyMemcpy(&(my_actual_path[MyWStrlen(work_path)]), file_name_pathw,
                 MyWStrlen(file_name_pathw) * sizeof(wchar_t));


        RtlInitUnicodeString_f(&unicodeString, my_actual_path);

        InitializeObjectAttributes(&objAttribs,
                                   &unicodeString,
                                   OBJ_CASE_INSENSITIVE,
                                   NULL,
                                   NULL);

        NtCreateFile_f(
            &hFile,
            FILE_GENERIC_READ,
            &objAttribs,
            &ioStatusBlock,
            &largeInteger,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            NULL);

        if (hFile != NULL)
        {
            IO_STATUS_BLOCK RioStatusBlock = { 0 };
            LARGE_INTEGER rlargeInteger = { 0 };
            char status_end = 0;

            do
            {
                NtReadFile_f(
                    hFile,
                    0,
                    NULL,
                    NULL,
                    &RioStatusBlock,
                    &status_end,
                    sizeof(status_end),
                    &rlargeInteger,
                    NULL
                );

                if (status_end == 0)
                {
                    LARGE_INTEGER interval = { 0 };
                    const int sleep_ms = 100;

                    interval.QuadPart = -1 * (int)(sleep_ms * 10000);

                    NtDelayExecution_f(false, &interval);
                }
            }
            while (status_end == 0);

            ZwClose_f(hFile);
        }
    }

    return retf;
}

int MyItoa(int value, char* sp, int radix)
{
    char tmp[16];
    char* tp = tmp;
    int i;
    unsigned v;

    int sign = (radix == 10 && value < 0);
    if (sign)
    {
        v = -value;
    }
    else
    {
        v = (unsigned)value;
    }

    while (v || tp == tmp)
    {
        i = v % radix;
        v /= radix;
        if (i < 10)
        {
            *tp++ = i + '0';
        }
        else
        {
            *tp++ = i + 'a' - 10;
        }
    }

    int len = tp - tmp;

    if (sign)
    {
        *sp++ = '-';
        len++;
    }

    while (tp > tmp)
    {
        *sp++ = *--tp;
    }

    return len;
}

void MyMemcpy(void* dest, void* src, size_t n)
{
    unsigned char* csrc = (unsigned char*)src;
    unsigned char* cdest = (unsigned char*)dest;

    for (int i = 0; i < n; i++)
    {
        cdest[i] = csrc[i];
    }
}

size_t MyWStrlen(wchar_t* str)
{
    unsigned char* ptr_str = (unsigned char*)str;
    size_t str_size = 0;

    while (true)
    {
        if (*ptr_str == 0 && *(ptr_str + 1) == 0)
        {
            break;
        }

        ptr_str += 2;
        str_size++;
    }

    return str_size;
}

void GetCax(void)
{
    return;
}




// Code from:
//
// NTSTATUS createStandardProcess(PUNICODE_STRING pProcessImageName)
// {
//     PS_CREATE_INFO procInfo;
//     RTL_USER_PROCESS_PARAMETERS userParams;
//     PS_ATTRIBUTE_LIST attrList;
//     PS_PROTECTION protectionInfo;
//
//     NTSTATUS status = STATUS_PENDING;
//     HANDLE hProcess = NULL;
//     HANDLE hThread = NULL;
//     ///We should supply a minimal environment (environment variables). Following one is simple yet fits our needs.
//     char data[2 * sizeof(ULONGLONG)] = { 'Y', 0x00, 0x3D, 0x00, 'Q', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
//
//
//     if (pProcessImageName)
//     {
//         RtlSecureZeroMemory(&protectionInfo, sizeof(protectionInfo));
//         RtlSecureZeroMemory(&userParams, sizeof(userParams));
//         RtlSecureZeroMemory(&attrList, sizeof(attrList));
//         RtlSecureZeroMemory(&procInfo, sizeof(procInfo));
//         RtlSecureZeroMemory(data, sizeof(data));
//
//         protectionInfo.Signer = (UCHAR)PsProtectedSignerNone;
//         protectionInfo.Type = (UCHAR)PsProtectedTypeNone;
//         protectionInfo.Audit = 0;
//
//         userParams.Length = sizeof(RTL_USER_PROCESS_PARAMETERS);
//         userParams.MaximumLength = sizeof(RTL_USER_PROCESS_PARAMETERS);
//         attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
//         procInfo.Size = sizeof(PS_CREATE_INFO);
//
//         userParams.Environment = (WCHAR*)data;
//         userParams.EnvironmentSize = sizeof(data);
//         userParams.EnvironmentVersion = 0;
//         userParams.Flags = RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
//
//         attrList.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE,
//                                            TRUE, FALSE);
//         attrList.Attributes[0].Size = pProcessImageName->Length;
//         attrList.Attributes[0].Value = (ULONG_PTR)pProcessImageName->Buffer;
//
//         status = ZwCreateUserProcess_f(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED,
//                                        NULL, NULL, CREATE_SUSPENDED, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, &userParams,
//                                        &procInfo,
//                                        &attrList);
//
//     }
//     else
//     {
//         status = STATUS_INVALID_PARAMETER;
//     }
//
//     return status;
// }
//
//
// #define PROCESS_LAUNCHED_NAMEW L"\\??\\C:\\Windows\\System32\\calc.exe"
//     UNICODE_STRING process_launched =
//     {
//         sizeof(PROCESS_LAUNCHED_NAMEW) - 2,
//         sizeof(PROCESS_LAUNCHED_NAMEW),
//         PROCESS_LAUNCHED_NAMEW
//     };
//
//     createStandardProcess(&process_launched);
