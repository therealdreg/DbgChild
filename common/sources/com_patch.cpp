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
#include "com_patch.h"

/*
TODO:
Refactorize
check memory operations & paths bounds etc
fix possibles buffers overflows, underruns etc.
Documentation
Consistent Variable Names
....
*/

size_t GetBytesInstructionsReplaced(
    void* address,
    void* address_to_show,
    size_t bytes_to_replaced,
    size_t max_bytes)
{
    csh handle = 0;
    cs_insn* insn;
    size_t count;
    size_t total_bytes = 0;
    cs_mode actual_cs_mode;

#ifdef _WIN64
    actual_cs_mode = CS_MODE_64;
#else
    actual_cs_mode = CS_MODE_32;
#endif

    if (cs_open(CS_ARCH_X86, actual_cs_mode, &handle) == CS_ERR_OK)
    {
        count = cs_disasm(handle, (uint8_t*)address, max_bytes, (uint64_t)address_to_show, 0,
            &insn);

        printf("Disasm count: %d\n", (int)count);
        if (count > 0)
        {
            size_t j;
            for (j = 0; j < count; j++)
            {
                printf("0x%" PRIXPTR " - ", (uintptr_t)insn[j].address);

                for (int k = 0; k < insn[j].size; k++)
                {
                    printf("0x%02X ", (int)((insn[j]).bytes[k]));
                }
                printf("- %s %s (%d bytes)\n", insn[j].mnemonic, insn[j].op_str, (int)(insn[j].size));
                total_bytes += insn[j].size;
                if (total_bytes >= bytes_to_replaced)
                {
                    break;
                }
            }

            cs_free(insn, count);

        }
        else
        {
            fprintf(stderr, "Error Disas Library\n");
        }
        cs_close(&handle);
    }
    else
    {
        fprintf(stderr, "Error Openning Disas Library\n");
    }

    return total_bytes;
}

BOOL CheckDangerousInstructions(void* address, void* address_to_show, size_t max_bytes)
{
    csh handle = 0;
    cs_insn* insn;
    size_t count;
    cs_mode actual_cs_mode;
    BOOL dangerous_inst_found = FALSE;

#ifdef _WIN64
    actual_cs_mode = CS_MODE_64;
#else
    actual_cs_mode = CS_MODE_32;
#endif

    if (cs_open(CS_ARCH_X86, actual_cs_mode, &handle) == CS_ERR_OK)
    {
        count = cs_disasm(handle, (uint8_t*)address, max_bytes, (uint64_t)address_to_show, 0,
            &insn);

        printf("Checking Dangerous Instructions (int3, jmp, call, ret, rip-relative...)\nDisasm count: %d\n", (int)count);
        if (count > 0)
        {
            size_t j;
            for (j = 0; j < count; j++)
            {
                if (
                    (strstr(insn[j].mnemonic, "jmp") != NULL) ||
                    (strstr(insn[j].mnemonic, "call") != NULL) ||
                    (strstr(insn[j].mnemonic, "ret") != NULL) ||
                    (strstr(insn[j].mnemonic, "int") != NULL) || // debugger interrupt??
                    ((insn[j].mnemonic)[0] == 'j') || // all kind of conditional jmps...
                    (strstr(insn[j].op_str, "rip") != NULL) // all RIP relative instr...
                    )
                {
                    fprintf(stderr, "WARNING: Dangerous instruction found:\n");
                    printf("0x%" PRIXPTR " - ", (uintptr_t)insn[j].address);
                    for (int k = 0; k < insn[j].size; k++)
                    {
                        printf("0x%02X ", (int)((insn[j]).bytes[k]));
                    }
                    printf("- %s %s (%d bytes)\n", insn[j].mnemonic, insn[j].op_str, (int)(insn[j].size));

                    dangerous_inst_found = TRUE;
                }
            }

            cs_free(insn, count);

        }
        else
        {
            fprintf(stderr, "Error Disas Library\n");
        }
        cs_close(&handle);
    }
    else
    {
        fprintf(stderr, "Error Openning Disas Library\n");
    }

    if (dangerous_inst_found == FALSE)
    {
        printf("OK - No Dangerous Instructions found!\n");
    }
    else
    {
        fprintf(stderr, "WARNING: Dangerous Instruction should cause a crash (maybe Debugger Breakpoints, AntiVirus hook installed before, etc.)\n");
    }

    return dangerous_inst_found;
}

BOOL PatchCode(
    HANDLE process,
    void* address,
    void* code,
    SIZE_T code_size,
    void* original_code,
    SIZE_T size_original_code,
    void* new_code,
    SIZE_T size_new_code
)
{
    SIZE_T bytes_written = 0;
    DWORD old_protect = 0;
    DWORD now_protect = 0;
    DWORD total_pages_size = (PAGE_ROUND_UP(((unsigned char*)address) + (code_size - 1)) - PAGE_ROUND_DOWN(address));

    printf("Number Total of bytes pages to change rights: %d ( %d pages )\n", total_pages_size, total_pages_size / PAGE_SIZE);

    VirtualProtectEx(process, (LPVOID)PAGE_ROUND_DOWN(address),
        total_pages_size,
        PAGE_EXECUTE_READWRITE,
        &old_protect);

    if (original_code != NULL)
    {
        ReadProcessMemory(process, address, original_code, size_original_code, &bytes_written);
    }

    WriteProcessMemory(process, address, code, code_size, &bytes_written);

    if (new_code != NULL)
    {
        ReadProcessMemory(process, address, new_code, size_new_code, &bytes_written);
    }

    VirtualProtectEx(process, (LPVOID)PAGE_ROUND_DOWN(address),
        total_pages_size,
        old_protect,
        &now_protect);

    return TRUE;
}