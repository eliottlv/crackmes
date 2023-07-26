BITS 64
%use altreg

%define loop_print_failed           0x8021f85f
%define loop_exit_1v1               0xd088ccc3

jmp .start
; ./encryptor.py "Failed !"\n + key
msg_failed dw           0x07c8,0x3906,0xf17e,0x8527,0xa341,0x41a9
len_failed equ          $-msg_failed

; syscall write (msg, size)
%macro write 2
    xor rax, rax
    jmp .write_rax
    db 0x20,0xef,0x77
    .write_stdout:
    mov rdi, rax    ; stdout
    jmp .write_char
    db 0x16,0x2c,0xc4,0x3d,0xd8,0x10,0x4f,0x7a,0x95,0x6e,0xea
    .write_rax:
    inc rax     ; write
    jmp .write_stdout
    db 0xe0,0x5a,0xb6,0xb3,0xd0,0x89,0xaa,0xc7
    .write_len:
    mov rdx, %2 ; len
    jmp .write_end
    db 0x30,0x10,0x88,0x36,0x59,0x42,0x16,0x84,0x5b,0xd0,0xeb,0x29,0xfb
    .write_char:
    mov rsi, %1 ; char *
    jmp .write_len
    db 0x88,0x5a,0xc0,0x54,0x3d,0xb9,0x8b
    jmp $-5
    .write_end:
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
    ; Args for decrypt_word
    add r10, %1
    mov rax, r10
    add r10, %2-2
    mov rbx, r10
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
    ; Clear registers
    xor r12, r12
    ; Loop control
    inc rcx
    inc rcx
    cmp rcx, %2-2
%endmacro

.start:
decrypt_msg msg_failed, len_failed
mov r10d, loop_print_failed
mov r11d, loop_exit_1v1
cmovne r15d, r10d
cmove r15d, r11d
cmove rcx, r12
