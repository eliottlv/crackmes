BITS 64

%define loop_dbg_found              0x1221a352
%define loop_print_prompt           0xfb439931

; Check for debugger (self ptrace)
xor rax, rax
jmp $+2
mov al, 0x9a
not al
syscall
mov rbx, loop_dbg_found
mov rcx, loop_print_prompt
cmp rax, 0
cmovne r15d, ebx
cmove r15d, ecx
