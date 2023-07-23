BITS 64
%use altreg

; TODO :
; - détection de débugeur (autre que ptrace).
; - plusieurs rounds de déchiffrement avec des clés différentes.
; - calcul des adresses de jump à l'exécution (avec xor des adresses avec une clé).
; - chiffrement du code avec une page mémoire rwx.
; - Plusieurs rounds de hashage.
; - Hash sur 128 octets.

%define loop_junk_bytes             0x511138d1
%define loop_print_prompt           0xfb439931
%define loop_fake_print_prompt      0x08fb90bf
%define loop_get_pass               0xb5cb80a2
%define loop_fake_get_pass          0xbe107b3c
%define loop_check_pass             0x6c5f8286
%define loop_fake_check_pass        0x344ee0b7
%define loop_exit_0                 0xdd8aeb7a
%define loop_exit_1                 0xdd2d38da
%define loop_exit_2                 0x8dff7d3f
%define loop_dbg_found              0x1221a352
%define loop_fake_dbg_found         0xc87d5f58
; %define loop_decrypt_code           0x85b34862
; %define loop_fake_decrypt_code      0x1044761d
%define loop_failed                 0x72605214
%define loop_fake_failed            0x02fe318b
%define loop_success                0xa5db20db
%define loop_fake_sucess            0xbf791a66

; syscall exit (code)
%macro exit 1
    mov rax, 0x3c
    mov rdi, %1
    syscall
%endmacro

; syscall read (dest, size)
%macro read 2
    mov rax, 0 ; read
    mov rdi, 0 ; stdin
    mov rsi, %1 ; char *
    mov rdx, %2 ; len
    syscall
%endmacro

; syscall write (msg, size)
%macro write 2
    mov rax, 1 ; write
    mov rdi, 1 ; stdout
    mov rsi, %1 ; char *
    mov rdx, %2 ; len
    syscall
%endmacro 

; Decrypt a 2 bytes data with a 2 bytes key.
; Arg1 (rax) : data ptr
; Arg2 (rbx) : key ptr
; Arg3 (rcx) : position in data
; Return : decrypted 2 bytes on stack
%macro decrypt_word 0
    ; Clean registers
    xor r6, r6
    mov r7, r6
    ; Get data & key
    mov r6w, [rax+rcx]
    mov r7w, [rbx]
    ; Rotate key
    ror r7w, cl
    ; data ^ key
    xor r6w, r7w
    ; Save data to stack (reverse order)
    mov r7b, r6b
    shr r6w, 8
    dec rsp
    mov byte [rsp], r7b
    dec rsp
    mov byte [rsp], r6b
    ; Clean registers
    xor r6, r6
    mov r7, r6
    mov r8, r7
%endmacro

; Decrypt & print msg (msg, size)
%macro decrypt_msg 2
    mov rcx, 0
    .decrypt_loop_%1:
    ; Args for decrypt_word
    mov rax, %1
    mov rbx, %1+%2-2
    decrypt_word
    ; Save counter
    mov r8, rcx
    ; Write data
    write rsp, 2
    ; Restore couter
    mov rcx, r8
    ; Remove data from stack
    inc rsp
    inc rsp
    ; Loop control
    inc rcx
    inc rcx
    cmp rcx, %2-2
    jne .decrypt_loop_%1
%endmacro

; %macro decrypt_data 0
;     mov rax, [_code+rcx]
;     mov rbx, [key]
;     xor rax, rbx
;     mov [_code+rcx], rax
;     add rcx, 8
;     mov r2d, loop_decrypt_code
;     mov r5d, loop_check_pass
;     cmp rcx, len_code
;     cmovne r15d, r2d
;     cmove r15d, r5d
;     xor r2, r2
;     mov r5, r2
; %endmacro

; Calculate hash
%macro hash 1
	mov rax, 0					; Loop counter (one iter)
	mov cl, byte [rsp]			; String size
	inc rsp
	; Clean registers
	xor r10, r10
    mov r11, r10
    mov r12, r10
    mov r13, r10
    mov r14, r10
	mov r15, r10
	mov r14d, dword [init1]		; Precedent result
	mov r15d, dword [init2]		; Precedent result
	.hash_loop%1:
	; First char
	mov r10b, [_buff+rax]
	;mov r10b, [msg+rax]		; Get one char
	mov r11b, r10b
	mov r12b, r10b
	mov r13b, r10b
	; Rotate
	ror r10b, 6
	ror r11b, 18
	ror r12b, 15
	ror r13b, 9
	; Shift
	shl r11d, 24
	shl r12d, 16
	shl r13d, 8
	; Extend output
	add r10d, r11d
	add r10d, r12d
	add r10d, r13d
	; Mix
	xor r10d, dword [key1]
	; Clear tmp registers
	xor r11, r11
	mov r12, r11
	mov r13, r11

	; Second char
	mov r9b, [_buff+rax+1]
	;mov r9b, [msg+rax+1]	; Get one char+1
	mov r11b, r9b
	mov r12b, r9b
	mov r13b, r9b
	; Rotate
	ror r9b, 17
	ror r11b, 3
	ror r12b, 18
	ror r13b, 7
	; Shift
	shl r11d, 24
	shl r12d, 16
	shl r13d, 8
	; Extend output
	add r9d, r11d
	add r9d, r12d
	add r9d, r13d
	; Mix
	xor r9d, dword [key2]
	; Clear tmp registers
	xor r11, r11
	mov r12, r11
	mov r13, r11

	; Mix with preceding result
	xor r9d, r14d
	xor r10d, r15d
	mov r14d, r9d
	mov r15d, r10d
	; Clean results
	xor r9, r9
	xor r10, r10

	; Loop control (one iter)
	inc rax
	cmp rax, pwd_len-1
	jne .hash_loop%1

	; Merge results
	shl r14, 32
	add r14, r15
%endmacro

section .bss
    _buff:
    buff resb       256         ; Reserver 256 octets
    buff_len equ    $-buff

section .data
    ; ./encryptor.py "Password : " + key
    msg_prompt dw           0xf2b6,0x9bc6,0x0d42,0x2cef,0xf798,0x95e8,0xa2d7
    len_prompt equ          $-msg_prompt
    ; ./encryptor.py "Debugger detected :-)"\n + key
    msg_dbg_detected dw     0xe41e,0x8a6b,0xdd60,0x8bf3,0x5bc4,0x7b9c,0x62d9,0xf58b,0xc45b,0xd233,0x930d,0xa07b
    len_dbg_detected equ    $-msg_dbg_detected
    ; ./encryptor.py "Success !"\n + key
    msg_success dw          0xaa07,0xdd3f,0x4ae4,0xb8c5,0x53f3,0xf972
    len_success equ         $-msg_success
    ; ./encryptor.py "Failed !"\n + key
    msg_failed dw           0xa46f,0xd1ef,0x8b44,0x1ba9,0x04e2,0xe20e
    len_failed equ          $-msg_failed
    ; check_failed_callkey dq             0x99e0251e08e0e7b2
    ; check_succes_callkey dq             0x4fd7fe1f8d6e5ea2
    ;key dq                              0x7af8eab5b4f28eb5      ; Key to decrypt .code
    real_hash dq	                    0xa33bca10f42fa712      ; Pwd : @vKZ6&@G49eK!7*3
    init1 dd		                    0x6a736414
	init2 dd		                    0xb0a2b143
	key1 dd			                    0x8fd381ed
	key2 dd			                    0x425f162a
    pwd_len equ                         16

section .text
global _start
_start:
    ; Random start selector
    ; Register r15 is used to store the switch evaluated data
    rdrand r15
    rdrand r14

    cmp r15, r14
    js .dbg_check_v1
    jns .dbg_check_v2

    .dbg_check_v1:
    ; Check for debugger (self ptrace)
    mov rax, 0x65
    syscall
    mov rbx, loop_dbg_found
    mov rcx, loop_print_prompt
    cmp rax, 0
    cmovne r15d, ebx
    cmove r15d, ecx 
    jmp .main_loop
    jmp .shit           ; Dead code
    db 0xfc,0x2b,0xed,0x73,0x02,0x2c,0x33,0xbc,0x69,0x6a,0x9d,0x5a

    .dbg_check_v2:
    ; Check for debugger (self ptrace)
    mov rax, 0x65
    syscall
    mov rbx, loop_dbg_found
    mov rcx, loop_print_prompt
    cmp rax, 0
    cmovne r15d, ebx
    cmove r15d, ecx
    jmp .main_loop
    jmp .shit           ; Dead code
    db 0x0a,0x16,0x25,0x3b,0x2a,0x6e,0x60,0xb0,0xd4,0xb8,0x62,0x8d,0xca,0x45,0xc0,0x47

    ;;;;;;;;;;;;;;;
    ;;;;;; Main Loop
    ;;;;;;;;;;;;;;;

    .main_loop:
    ; Switch statement for CFG flattening
    ; Some switch cases are not reachable. They're just here to mislead the decompiler.
    ; r15d is user to check the cases.
    cmp r15d, loop_exit_1
    je .exit_1
    cmp r15d, loop_failed
    je .print_failed+14
    cmp r15d, loop_fake_get_pass
    je .get_pass
    cmp r15d, loop_check_pass
    je .check_pass+22
    cmp r15d, loop_success
    je .print_success+25
    cmp r15d, loop_print_prompt
    je .print_prompt+16
    cmp r15d, loop_fake_print_prompt
    je .print_prompt
    cmp r15d, loop_fake_failed
    je .print_failed
    ; cmp r15d, loop_decrypt_code
    ; je .decrypt_code+24
    cmp r15d, loop_dbg_found
    je .dbg_found+44
    cmp r15d, loop_get_pass
    je .get_pass+14
    cmp r15d, loop_fake_sucess
    je .print_success
    cmp r15d, loop_fake_dbg_found
    je .dbg_found
    ; cmp r15d, loop_fake_decrypt_code
    ; je .decrypt_code
    cmp r15d, loop_exit_0
    je .exit_0
    cmp r15d, loop_fake_check_pass
    je .check_pass
    cmp r15d, loop_junk_bytes
    je .junk_bytes
    cmp r15d, loop_exit_2
    je .exit_2
    db 0xe9,0xfb,0xe5,0x1e,0x26,0xcf,0xfb,0x74,0x4e,0xf5,0x19,0xd0,0x31,0x9e,0x07,0xaf,0xee,0x3f,0x75,0x20,0x7f,0x9e,0xb5,0x14,0x3f,0x55,0x63,0xcd,0xd9,0x88,0x1e,0x7b,0xb0,0xf6,0x19,0x21,0xe0,0xb0,0x00,0x7a,0x31,0x8d,0xdd,0x62,0x14,0x99,0x99,0x56,0xa4,0x3f,0x72,0xf5,0xb1,0x84,0xea,0x62,0xe7,0x10,0x99,0x51,0xe0,0x4f,0x0a,0xaa,0x54,0xec

    ; Print debugger found and exit 2
    .dbg_found:
    db 0x73,0x59,0xa8,0x05,0x19,0x02,0x25,0xb3,0xbb,0x9e,0xe8,0xfc,0x68,0x13,0x1a,0xaf,0x1a,0xa4,0x73,0x15,0xe8,0xe9,0xdb,0xc2,0xdf,0x84,0x56,0xaa,0x25,0x83,0x15,0x8d,0x58,0x65,0x87,0x60,0x49,0x2f,0xa4,0x81,0xa2,0x04,0xbd,0xe6
    decrypt_msg msg_dbg_detected, len_dbg_detected
    mov r15d, loop_exit_2
    jmp .main_loop
    db 0x19,0xbf,0x0d,0xd3,0xd2,0xe0,0xda,0x03,0x99,0x50,0x61,0xd7,0x9d,0xc9

    .junk_bytes:
    ; Junk bytes
    rdrand rax
    imul rax, 0x04
    cmp rax, 0xfe
    je .shit
    jne .shit
    mov r15d, loop_junk_bytes
    jmp .main_loop
    db 0xe9,0x3d,0xd5,0x44,0x39,0xad,0x4e,0xeb,0x2b,0x18,0x10

    .print_prompt:
    ; Print prompt
    db 0x1a,0x6e,0xd2,0x80,0xca,0x73,0x9c,0x0f,0xf6,0xb5,0x81,0xcb,0x35,0xc5,0xe3,0x19
    decrypt_msg msg_prompt, len_prompt
    mov r15d, loop_get_pass
    jmp .main_loop
    db 0x53,0xc1,0xfa,0x36,0x5b,0x57,0x94,0x9d,0x4d,0x5c,0x1f,0x79,0x4b,0xb2

    .get_pass:
    ; Store input password
    db 0x29,0xe1,0x26,0x5f,0xa5,0xef,0xfd,0xab,0xf7,0x25,0x3d,0x54,0x16,0xc7
    read buff, buff_len
    mov r15d, loop_check_pass
    jmp .main_loop
    db 0x89,0xcc,0x49,0x0c,0xc9,0xa8,0xf9,0x84,0x90,0x4b,0x60,0x30,0xc9,0x9b,0x1b,0x81,0xfd,0x60,0xad,0x84

    .check_pass:
    ; Check password
    db 0xae,0x7a,0x5a,0xab,0xe7,0xf0,0xf8,0x5c,0x24,0x7f,0x0c,0x27,0xb9,0xf6,0xf0,0xbb,0x25,0xdf,0x3d,0x1f,0x52,0xcd
    ; Add string size
    dec rsp
	mov byte [rsp], byte pwd_len
    hash 0
    ; Compare hash
    cmp r14, [real_hash]
    mov rbx, loop_success
    mov rcx, loop_failed
    cmove r15d, ebx
    cmovne r15d, ecx
    jmp .main_loop
    db 0xc1,0x96,0x9c,0x80,0xcd,0x02,0x53,0x6d,0x65,0xf0,0xf3,0x54,0xe5,0x0d,0x0e,0xd3,0x7d

    ; .decrypt_code:
    ; ; Decrypt the .code section to retreive the password
    ; db 0xe4,0x8d,0xa5,0xb6,0x30,0x43,0x9c,0xfe,0x70,0xd7,0x38,0x69,0x08,0xfc,0x67,0x48,0x61,0x4a,0x3c,0x02,0x2c,0xc6,0x89,0xab
    ; decrypt_data
    ; jmp .main_loop
    ; db 0x0b,0x32,0xc5,0xd2,0xa1,0x71,0x97,0xa3,0x8f,0xe1,0x4b,0x26

    .print_success:
    db 0x80,0xe9,0x76,0x94,0x0a,0x24,0x91,0x19,0x92,0x30,0xd8,0xcd,0x5d,0x56,0x61,0xa7,0xb7,0xcc,0xc0,0x81,0x72,0xc0,0x68,0xb9,0x27
    decrypt_msg msg_success, len_success
    mov r15d, loop_exit_0
    jmp .main_loop
    db 0x40,0x51,0x5a,0x2f,0x8b,0x76,0xfc,0x0a,0x0b,0x9c,0x96,0x40

    .print_failed:
    db 0x9c,0x4c,0x97,0x7a,0xe3,0xf1,0x35,0x22,0x13,0xe3,0x42,0x76,0xdf,0xd8
    decrypt_msg msg_failed, len_failed
    mov r15d, loop_exit_1
    jmp .main_loop
    db 0x7d,0x91,0x3b,0x96,0x86,0x79,0xd3,0xde,0x06,0x4f,0x29,0xc4,0x26,0xae,0x1e,0xbb,0x2f,0xf5,0xe4,0xc1,0xe1,0xbd,0xc0

    .exit_0:
    exit 0
    db 0x83,0x87,0xb0,0xc6,0x19,0x84,0x3e,0x3d
    call .main_loop         ; Dead code

    .exit_1:
    exit 1
    db 0x46,0x10,0x6c,0xcf,0x8b,0x1a,0xf5,0xae,0xea,0xd2,0x93,0x01,0x37,0x75,0x48,0x5e,0x66
    call .main_loop         ; Dead code

    .exit_2:
    exit 2
    db 0xef,0x99,0x95,0x93,0x62,0xaf,0x28
    jmp .main_loop          ; Dead code

    ;;;;;;;;;;
    ;;;; Functions
    ;;;;;;;;;;

    ; ./genbytes.py 100
    .shit:
    db  0x36,0xcd,0x36,0x3b,0x06,0x15,0x7f,0x84,0x74,0x61, \
        0xc8,0xab,0x7d,0x74,0x0f,0x4d,0xdd,0x39,0x95,0xbb, \
        0x4a,0x20,0xac,0xc1,0x11,0x83,0xd3,0x9b,0xbb,0x47, \
        0x4f,0xd6,0xb1,0xf5,0x74,0xcd,0xbd,0x47,0x22,0x2a, \
        0x2c,0x3f,0x14,0xdd,0x2a,0x77,0x15,0x57,0xee,0xb6, \
        0x31,0x2c,0x8f,0xf0,0x96,0x54,0x1b,0xe0,0x0f,0xe9, \
        0x4a,0x2c,0x20,0xbd,0x04,0x28,0x6c,0x09,0x94,0x54, \
        0xe7,0xa9,0x3a,0x3b,0xa4,0x11,0xf3,0x47,0x6b,0xd5, \
        0xbc,0x80,0x9c,0x48,0x63,0xf2,0xc4,0xd4,0x64,0x48, \
        0xb5,0x9f,0xe2,0xbf,0xf9,0x4b,0xa0,0x14,0x65,0xce

    ; Calculate call address
    ; mov rax, 0x4fd7fe1f8d2e4ed3     ; Encrypted address .main_loop
    ; mov rbx, [check_succes_callkey]
    ; xor rax, rbx
    ; jmp rax