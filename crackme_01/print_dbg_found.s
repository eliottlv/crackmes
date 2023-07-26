BITS 64
%use altreg

%define loop_dbg_found              0x1221a352
%define loop_exit_1v2               0x8dff7d3f

jmp .start
; ./encryptor.py "Debugger detected :-)"\n + key
msg_dbg_detected dw     0x554f,0xe63f,0xc675,0xcd36,0x0a75,0x2ff0,0x77c2,0x30cd,0x750a,0xbe67,0x8818,0x112a
len_dbg_detected equ    $-msg_dbg_detected

; syscall write (msg, size)
%macro write 2
    xor rax, rax
    jmp .write_rax
    db 0x78,0x6a,0xed,0x65
    .write_stdout:
    mov rdi, rax    ; stdout
    jmp .write_char
    db 0xb4,0xbc,0x01,0xaf,0xb9,0x51,0x10
    .write_rax:
    inc rax     ; write
    jmp .write_stdout
    db 0xed,0x32,0x62,0x4f,0x56,0x9e
    .write_len:
    mov rdx, %2 ; len
    jmp .write_end
    db 0x4b,0x57,0x07,0xba
    .write_char:
    mov rsi, %1 ; char *
    jmp .write_len
    db 0x48,0x43,0xbb
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
decrypt_msg msg_dbg_detected, len_dbg_detected
mov r10d, loop_dbg_found
mov r11d, loop_exit_1v2
cmovne r15d, r10d
cmove r15d, r11d
cmove rcx, r12
