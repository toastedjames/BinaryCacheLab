global _start
section .text
_start:
    mov edi, 6
    call factorial
    cmp rax, 720
    jne .bad
    mov eax, 1
    mov edi, 1
    lea rsi, [rel message]
    mov edx, 4
    syscall
    xor edi, edi
    mov eax, 60
    syscall
.bad:
    mov edi, 1
    mov eax, 60
    syscall
factorial:
    cmp rdi, 1
    jbe .base
    push rdi
    dec rdi
    call factorial
    pop rdi
    imul rax, rdi
    ret
.base:
    mov eax, 1
    ret
section .rodata
message: db "720", 10
