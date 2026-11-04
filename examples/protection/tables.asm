default rel
global _start:function
global lookup:function (lookup_end-lookup)
global table0:data (table0_end-table0)
global table1:data (table1_end-table1)
section .text
_start:
    cmp qword [rsp],2
    jne .invalid
    mov rax,[rsp+16]
    movzx edi,byte [rax]
    sub edi,48
    and edi,1
    call lookup
    cmp eax,18
    jne .invalid
    xor edi,edi
    jmp .exit
.invalid:
    mov edi,3
.exit:
    mov eax,60
    syscall
lookup:
    lea rcx,[rel table0]
    mov eax,[rcx+rdi*4]
    lea rcx,[rel table1]
    mov edx,[rcx+rdi*4]
    add eax,edx
    ret
lookup_end:
section .data align=64
times 48 db 0
table0: dd 7,7
table0_end:
table1: dd 11,11
table1_end:
section .note.GNU-stack noalloc noexec nowrite progbits
