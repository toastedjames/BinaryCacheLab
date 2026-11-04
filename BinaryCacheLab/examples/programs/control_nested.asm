global _start
section .text
_start:
    call outer
    xor edi, edi
    mov eax, 60
    syscall
outer:
    call inner
    ret
inner:
    mov eax, 1
    mov edi, 1
    lea rsi, [rel message]
    mov edx, 7
    syscall
    ret
section .rodata
message: db "NESTED", 10
