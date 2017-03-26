;
; DbgChild - Create Process Patch
; -
; MIT License
; -
;  (c) <2017> <David Reguera Garcia aka Dreg>
; http://www.fr33project.org/
; https://github.com/David-Reguera-Garcia-Dreg
; dreg@fr33project.org
; -
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
; 
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
; 
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.
;

IFDEF RAX
CAX EQU RAX
CBX EQU RBX
ELSE
CAX EQU EAX
CBX EQU EBX
.486
.model flat, C
option casemap:none 
ENDIF

; ------ COMMON PAYLOAD

.code

payload PROC

init_payload::

nop
jmp payload_ep_lbl

ldr_get_procedure_address_lbl::
ldr_get_procedure_address db    8 dup(?) ;

ldr_load_dll_sym_lbl::
ldr_load_dll_sym db    8 dup(?) ;

dll_unicode_string_lbl::
dll_unicode_string      db    16 dup(?) ;

dll_ansi_string_lbl::
dll_ansi_string      db    16 dup(?) ;

dll_full_path_lbl::
dll_full_path      db    520 dup (?) ;

dll_func_name_lbl::
dll_func_name      db    520 dup (?) ;

nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

; START DATA PASSED TO DLL IN CAX - DONT MODIFY THIS!!! - THE DLL ASSUME THIS ORDER
trampoline_lbl::
trampoline      db    80 dup (?) ;

dll_work_full_path_lbl::
dll_work_full_path      db    520 dup (?) ;
; -----

nop
nop
nop
nop
nop
nop
nop
nop
nop
nop

nop

payload_ep_lbl:

IFDEF RAX

; ------ x64 PAYLOAD

push rbx
push rcx
push rdx
push rsi
push rdi
push r8
push r9
push r10
push r12
push r13
push r14
push r15

push rbp ; save frame pointer
mov rbp, rsp ; fix stack pointer
sub rsp, 8 * (4 + 2) ; allocate shadow register area + 2 QWORDs for stack alignment

push 0
mov rcx, rsp
push 0
mov rdx, rsp
lea r8, dll_unicode_string
push 0
mov r9, rsp

mov rdi, rsp
and rsp, not 8 ; align stack to 16 bytes prior to API call
lea rax, ldr_load_dll_sym
mov rsi, rbp
call qword ptr [rax]
mov rbp, rsi

mov rcx, rdi
mov rcx, [rcx]
lea rdx, dll_ansi_string
xor r8, r8
push 0
mov r9, rsp

mov rdi, rsp
and rsp, not 8 ; align stack to 16 bytes prior to API call
lea rax, ldr_get_procedure_address
mov rsi, rbp
call qword ptr [rax]
mov rbp, rsi

mov r11, [rdi]

mov rsp, rbp
pop rbp

nop

pop r15
pop r14
pop r13
pop r12
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx

push rbx
push rcx
push rdx
push rsi
push rdi
push r8
push r9
push r10
push r12
push r13
push r14
push r15

lea rax, [rsp+90h+28h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

lea rax, [rax-08h]
push [rax]

and rsp, not 8 ; align stack to 16 bytes prior to API call

lea rax, trampoline
call r11

pop r15
pop r15
pop r15
pop r15
pop r15
pop r15
pop r15
pop r15
pop r15
pop r15
pop r15

pop r15
pop r14
pop r13
pop r12
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx

ret

nop
int 3

ELSE 

; ------ x86 PAYLOAD

pushad
pushfd

call delta
delta:
pop ebp
sub ebp, OFFSET delta

lea eax, [ebp+dll_unicode_string]

push 0
push 0

push esp
push eax
push esp
add dword ptr [esp], 12
push esp
add dword ptr [esp], 16

lea eax, [ebp+ldr_load_dll_sym]
call dword ptr [eax]

pop eax

push esp
push 0
lea ebx, [ebp+dll_ansi_string]
push ebx
push eax
lea eax, [ebp+ldr_get_procedure_address]
call dword ptr [eax]

pop edx

mov dword ptr [esp+18h], edx
lea eax, [ebp+trampoline]
mov dword ptr [esp+20h], eax

popfd
popad

pushad
pushfd

lea ebx, [esp+24h+(4*11)]
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx]
sub ebx, 4
push dword ptr [ebx] 
call edx

mov dword ptr [esp+20h], eax
popfd
popad

ret

nop
int 3

ENDIF

end_payload::

payload ENDP

; ------ COMMON PAYLOAD API

get_payload_size PROC
PUSH CBX
LEA CAX, OFFSET end_payload
LEA CBX, OFFSET init_payload
SUB CAX, CBX
POP CBX
RET
get_payload_size ENDP

get_payload_ep PROC
LEA CAX, OFFSET init_payload
RET
get_payload_ep ENDP

get_payload_dll_str PROC
LEA CAX, OFFSET dll_full_path_lbl
RET
get_payload_dll_str ENDP

get_payload_dll_unicode_str PROC
LEA CAX, OFFSET dll_unicode_string_lbl
RET
get_payload_dll_unicode_str ENDP

get_payload_ldr_load_dll_sym PROC
LEA CAX, OFFSET ldr_load_dll_sym_lbl
RET
get_payload_ldr_load_dll_sym ENDP

get_payload_get_procedure_address PROC
LEA CAX, OFFSET ldr_get_procedure_address_lbl
RET
get_payload_get_procedure_address ENDP

get_payload_dll_func_name PROC
LEA CAX, OFFSET dll_func_name_lbl
RET
get_payload_dll_func_name ENDP

get_payload_dll_ansi_string PROC
LEA CAX, OFFSET dll_ansi_string_lbl
RET
get_payload_dll_ansi_string ENDP

get_trampoline PROC
LEA CAX, OFFSET trampoline_lbl
RET
get_trampoline ENDP

get_dll_work_full_path PROC
LEA CAX, OFFSET dll_work_full_path_lbl
RET
get_dll_work_full_path ENDP

	
END