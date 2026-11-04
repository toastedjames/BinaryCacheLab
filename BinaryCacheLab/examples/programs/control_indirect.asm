global _start
section .text
_start:
    lea rax, [rel selected]
    call rax
    xor edi, edi
    mov eax, 60
    syscall
selected:
    mov eax, 1
    mov edi, 1
    lea rsi, [rel message]
    mov edx, 9
    syscall
    ret
section .rodata
message: db "INDIRECT", 10
