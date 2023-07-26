BITS 64

%define loop_dbg_found              0xcd8699c1
%define loop_print_prompt           0xa8c20c6e

; Check for debugger (self ptrace)
xor rax, rax
inc rax
jmp $+2                 ; 2 bytes instr jump
shl rax, 1
inc rax
shl rax, 5
jmp $+6
db 0xa0
jmp $+5
db 0x33
jmp $-3                 ; Jump to middle of instruction
add rax, 0x05
syscall
mov rbx, loop_dbg_found
mov rcx, loop_print_prompt
cmp rax, 0
cmovne r15d, ebx
cmove r15d, ecx
