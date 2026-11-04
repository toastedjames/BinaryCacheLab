extern _ITM_deregisterTMCloneTable
extern _ITM_registerTMCloneTable
extern __cxa_finalize
extern __gmon_start__
extern __libc_start_main
extern __printf_chk
extern exit


global _IO_stdin_used
global __TMC_END__
global __bss_start
global __data_start
global __dso_handle
global _edata
global _end
global _fini
global _init
global _start
global main
global secret_lookup


default rel


; ----------------
; Function: _start
; ----------------
; Entry 1060; block 0; address 1060
_start:
  XOR EBP, EBP
  MOV R9, RDX
  POP RSI
  MOV RDX, RSP
  AND RSP, 0xfffffffffffffff0
  PUSH RAX
  PUSH RSP
  XOR R8D, R8D
  XOR ECX, ECX
  LEA RDI, [main]    ; 0x115f --> main
  CALL __libc_start_main wrt ..plt

; Entry 1060; block 1; address 1085
L1060_1:
  HLT




; ------------------------------
; Function: deregister_tm_clones
; ------------------------------
; Entry 1090; block 0; address 1090
deregister_tm_clones:
  LEA RDI, [__TMC_END__]    ; 0x4080 --> __TMC_END__
  LEA RAX, [__TMC_END__]    ; 0x4080 --> __TMC_END__
  CMP RAX, RDI
  JE L1090_2    ; 0x10b8 --> L1090_2

; Entry 1090; block 1; address 10a3
L1090_1:
  MOV qword [Ltemp_storage_foxdec], RBX ; inserted
  LEA RBX, [_ITM_deregisterTMCloneTable wrt ..plt]
  MOV RAX, RBX
  MOV RBX, qword [Ltemp_storage_foxdec] ; inserted
  TEST RAX, RAX
  JE L1090_2    ; 0x10b8 --> L1090_2

; Entry 1090; block 3; address 10af
L1090_3:
  ; Resolved indirection: RAX --> _ITM_deregisterTMCloneTable
  JMP _ITM_deregisterTMCloneTable wrt ..plt

; Entry 1090; block 2; address 10b8
L1090_2:
  RET




; -------------------------------
; Function: __do_global_dtors_aux
; -------------------------------
; Entry 1100; block 0; address 1100
__do_global_dtors_aux:
  CMP byte [__TMC_END__], 0x0    ; 0x4080 --> __TMC_END__
  JNE L1100_2    ; 0x1138 --> L1100_2

; Entry 1100; block 1; address 110d
L1100_1:
  PUSH RBP
  MOV qword [Ltemp_storage_foxdec], RAX ; inserted
  LEA RAX, [__cxa_finalize wrt ..plt]
  CMP RAX, 0x0
  MOV RAX, qword [Ltemp_storage_foxdec] ; inserted
  MOV RBP, RSP
  JE L1100_4    ; 0x1127 --> L1100_4

; Entry 1100; block 3; address 111b
L1100_3:
  MOV RDI, qword [__dso_handle]    ; 0x4008 --> __dso_handle
  CALL __cxa_finalize wrt ..plt

; Entry 1100; block 4; address 1127
L1100_4:
  CALL deregister_tm_clones    ; 0x1090 --> deregister_tm_clones

; Entry 1100; block 5; address 112c
L1100_5:
  MOV byte [__TMC_END__], 0x1    ; 0x4080 --> __TMC_END__
  POP RBP
  RET

; Entry 1100; block 2; address 1138
L1100_2:
  RET




; ---------------------
; Function: frame_dummy
; ---------------------
; Entry 1140; block 1; address 10e4
L1140_1:
  MOV qword [Ltemp_storage_foxdec], RBX ; inserted
  LEA RBX, [_ITM_registerTMCloneTable wrt ..plt]
  MOV RAX, RBX
  MOV RBX, qword [Ltemp_storage_foxdec] ; inserted
  TEST RAX, RAX
  JE L1140_2    ; 0x10f8 --> L1140_2

; Entry 1140; block 3; address 10f0
L1140_3:
  ; Resolved indirection: RAX --> _ITM_registerTMCloneTable
  JMP _ITM_registerTMCloneTable wrt ..plt

; Entry 1140; block 2; address 10f8
L1140_2:
  RET

; Entry 1140; block 0; address 1140
frame_dummy:
  LEA RDI, [__TMC_END__]    ; 0x4080 --> __TMC_END__
  LEA RSI, [__TMC_END__]    ; 0x4080 --> __TMC_END__
  SUB RSI, RDI
  MOV RAX, RSI
  SHR RSI, 0x3f
  SAR RAX, 0x3
  ADD RSI, RAX
  SAR RSI, 0x1
  JE L1140_2    ; 0x10f8 --> L1140_2
  JMP L1140_1 ; jump is inserted




; -----------------------
; Function: secret_lookup
; -----------------------
; Entry 1149; block 0; address 1149
secret_lookup:
  TEST EDI, EDI
  JE L1149_2    ; 0x1158 --> L1149_2

; Entry 1149; block 1; address 1151
L1149_1:
  MOV EAX, dword [L_.data_0x407c]    ; 0x407c --> L_.data_0x407c
  RET

; Entry 1149; block 2; address 1158
L1149_2:
  MOV EAX, dword [L_.data_0x4078]    ; 0x4078 --> L_.data_0x4078
  RET




; --------------
; Function: main
; --------------
; Entry 115f; block 0; address 115f
main:
  MOV EAX, 0x1
  CMP EDI, 0x2
  JNE L115f_2    ; 0x1182 --> L115f_2

; Entry 115f; block 1; address 116d
L115f_1:
  MOV RDX, qword [RSI + 0x8]
  MOVZX EDI, byte [RDX]
  LEA ECX, [RDI - 0x30]
  CMP CL, 0x1
  JA L115f_2    ; 0x1182 --> L115f_2

; Entry 115f; block 3; address 117c
L115f_3:
  CMP byte [RDX + 0x1], 0x0
  JE L115f_4    ; 0x1183 --> L115f_4

; Entry 115f; block 2; address 1182
L115f_2:
  RET

; Entry 115f; block 4; address 1183
L115f_4:
  SUB RSP, 0x8
  MOVSX EDI, DIL
  SUB EDI, 0x30
  CALL secret_lookup    ; 0x1149 --> secret_lookup

; Entry 115f; block 5; address 1193
L115f_5:
  MOV EDX, EAX
  LEA RSI, [L_.rodata_0x2004]    ; 0x2004 --> L_.rodata_0x2004
  MOV EDI, 0x2
  MOV EAX, 0x0
  CALL __printf_chk wrt ..plt

; Entry 115f; block 6; address 11ab
L115f_6:
  MOV EAX, 0x0
  ADD RSP, 0x8
  RET




section .rodata align=4 ; @2000
L_.rodata_0x2000:
db 01h
db 00h
db 02h
db 00h
L_.rodata_0x2004:
db `%u\n`, 0; @ 2004
__GNU_EH_FRAME_HDR:

section .init_array align=8 ; @3db8
L_.init_array_0x3db8:
L_reloc_0x3db8_0x1140:
dq frame_dummy    ; 0x1140 --> frame_dummy
L_.init_array_END:

section .fini_array align=8 ; @3dc0
L_.fini_array_0x3dc0:
L_reloc_0x3dc0_0x1100:
dq __do_global_dtors_aux    ; 0x1100 --> __do_global_dtors_aux
L_.fini_array_END:




section .data align=64 ; @4000
__data_start:
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
__dso_handle:
dq __dso_handle    ; 0x4008 --> __dso_handle
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
db 00h
L_.data_0x4078:
db 07h
db 00h
db 00h
db 00h
L_.data_0x407c:
db 07h
db 00h
db 00h
db 00h
L_.data_END:




section .bss align=1 ; @4080
__TMC_END__:
resb 8
L_.bss_END:









section .bss
Ltemp_storage_foxdec:
resb 8