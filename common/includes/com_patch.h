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

#ifndef _COM_PATCH_H__
#define _COM_PATCH_H__

#include <windows.h>
#include "capstone.h"
#include "com_common.h"

BOOL CheckDangerousInstructions(void* address, void* address_to_show, size_t max_bytes);

size_t GetBytesInstructionsReplaced(void* address, 
    void* address_to_show,
    size_t bytes_to_replaced,
    size_t max_bytes);

BOOL PatchCode(
    HANDLE process, 
    void* address, 
    void* code, 
    SIZE_T code_size, 
    void* original_code, 
    SIZE_T size_original_code, 
    void* new_code, 
    SIZE_T size_new_code
);

#endif /* _COM_PATCH_H__ */