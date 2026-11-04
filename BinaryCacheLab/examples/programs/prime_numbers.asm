section .bss
    buf resb 20

section .text
    global _start

_start:
    mov r12, 2

.loop:
    cmp r12, 1000
    jg .done

    mov rdi, r12
    call is_prime
    test rax, rax
    jz .next

    mov rax, r12
    call print_num

.next:
    inc r12
    jmp .loop

.done:
    mov eax, 60
    xor edi, edi
    syscall

is_prime:
    cmp rdi, 2
    jb .no
    mov rcx, 2

.check:
    mov rax, rcx
    imul rax, rax
    cmp rax, rdi
    jg .yes

    mov rax, rdi
    xor edx, edx
    div rcx
    test rdx, rdx
    jz .no

    inc rcx
    jmp .check

.yes:
    mov eax, 1
    ret

.no:
    xor eax, eax
    ret

print_num:
    lea rsi, [buf + 19]
    mov byte [rsi], 10
    mov rbx, 10
    mov rcx, 1

.convert:
    xor edx, edx
    div rbx
    dec rsi
    add dl, '0'
    mov [rsi], dl
    inc rcx
    test rax, rax
    jnz .convert

    mov rdx, rcx
    mov rdi, 1
    mov eax, 1
    syscall
    ret
