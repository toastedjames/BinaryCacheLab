default rel
section .text
global read_pair
read_pair:
    mov eax, dword [region_a]
    add eax, dword [region_b]
    ret
section .data align=64
times 56 db 0
region_a:
db 7,0,0,0
region_a_end:
region_b:
db 7,0,0,0
region_b_end:
times 64 db 0
region_c:
db 9,0,0,0
region_c_end:
