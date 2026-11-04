default rel
global main:function
extern puts
section .text
main:
    push rbp
    mov rbp,rsp
    lea rdi,[rel message]
    call puts wrt ..plt
    xor eax,eax
    pop rbp
    ret
section .rodata
message: db "Hello, World",0
section .note.GNU-stack noalloc noexec nowrite progbits
