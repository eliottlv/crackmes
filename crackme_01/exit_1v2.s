BITS 64

xor rax, rax
jmp $+2
rdrand rbx
cmp rax, rbx
nop
js $+5
jns $+7
db 0x43
jmp $+6
db 0xa1, 0x3a
jmp $+2
db 0x95, 0x93
mov rax, 0x3a
inc rax
inc rax
mov rdi, 0
inc rdi
syscall
; Dead code
cmovne rax, r12
jmp $-12
aesdec xmm0, xmm1
cmovs rax, rbx
