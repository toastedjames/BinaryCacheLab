global _start
section .text
_start:
    mov ecx, 10
    xor ebx, ebx
.loop:
    add ebx, ecx
    dec ecx
    jnz .loop
    cmp ebx, 55
    jne .bad
    mov eax, 1
    mov edi, 1
    lea rsi, [rel message]
    mov edx, 3
    syscall
    xor edi, edi
    mov eax, 60
    syscall
.bad:
    mov edi, 1
    mov eax, 60
    syscall
section .rodata
message: db "OK", 10
