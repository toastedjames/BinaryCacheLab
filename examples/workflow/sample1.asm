default rel
global main:function
global lookup:function (lookup_end-lookup)
global group:data (group_end-group)
extern printf
section .text
main:
    push rbp
    mov rbp,rsp
    cmp edi,2
    jne .invalid
    mov rax,[rsi+8]
    movzx eax,byte [rax]
    sub eax,48
    and eax,1
    mov edi,eax
    call lookup
    mov esi,eax
    lea rdi,[rel fmt]
    xor eax,eax
    call printf wrt ..plt
    xor eax,eax
    pop rbp
    ret
.invalid:
    mov eax,2
    pop rbp
    ret
lookup:
    test edi,edi
    jz .zero
    mov eax,[rel group+4]
    ret
.zero:
    mov eax,[rel group]
    ret
lookup_end:
section .rodata
fmt: db "%u",10,0
section .data align=64
times 56 db 0
group: dd 7,7
group_end:
section .note.GNU-stack noalloc noexec nowrite progbits
