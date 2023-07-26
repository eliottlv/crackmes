BITS 64
%use altreg

%define loop_print_prompt           0xfb439931
%define loop_get_pass               0xb5cb80a2

jmp .start
; ./encryptor.py "Password : " + key
msg_prompt dw           0x46e6,0xb6d2,0x0607,0x6e3e,0xa72c,0x81c5,0x1687
len_prompt equ          $-msg_prompt

; syscall write (msg, size)
%macro write 2
    xor rax, rax
    jmp .write_rax
    db 0xe8,0x66,0x0a,0x31,0x26,0x91
    .write_stdout:
    mov rdi, rax    ; stdout
    jmp .write_char
    db 0x1e,0x88,0x0b
    .write_rax:
    inc rax     ; write
    jmp .write_stdout
    db 0x23,0xf5,0xfc,0x37,0xad,0xb1,0x3f,0x9a,0xcb,0x4a
    .write_len:
    mov rdx, %2 ; len
    jmp .write_end
    db 0xc7,0x57,0x7a,0x81,0xd1
    .write_char:
    mov rsi, %1 ; char *
    jmp .write_len
    db 0xb1,0x36
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
decrypt_msg msg_prompt, len_prompt
mov r10d, loop_print_prompt
mov r11d, loop_get_pass
cmovne r15d, r10d
cmove r15d, r11d
cmove rcx, r12
