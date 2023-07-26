BITS 64
%use altreg

%define loop_print_success          0x50a4d741
%define loop_exit_0                 0xdd8aeb7a

jmp .start
; ./encryptor.py "Success !"\n + key
msg_success dw          0x5306,0xa37f,0x5574,0xbf21,0x520a,0x0073
len_success equ         $-msg_success

; syscall write (msg, size)
%macro write 2
    xor rax, rax
    jmp .write_rax
    db 0x39,0xdc,0x5e,0x72,0x86
    .write_stdout:
    mov rdi, rax    ; stdout
    jmp .write_char
    db 0x5e,0x03,0x91,0x07,0x68,0x68,0x5e,0x5c,0x29
    .write_rax:
    inc rax     ; write
    jmp .write_stdout
    db 0x0b,0x1b,0xb8,0x4a,0xd8
    .write_len:
    mov rdx, %2 ; len
    jmp .write_end
    db 0xc4,0xe2,0xa7,0x8f,0x38,0xfb,0xd1
    .write_char:
    mov rsi, %1 ; char *
    jmp .write_len
    db 0x2b,0x80,0x9d,0xc0,0x66,0x43,0x28,0xa3
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
decrypt_msg msg_success, len_success
mov r10d, loop_print_success
mov r11d, loop_exit_0
cmovne r15d, r10d
cmove r15d, r11d
cmove rcx, r12
