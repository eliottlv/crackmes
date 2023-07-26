BITS 64
%use altreg

; Input :
; - r10 : code offset
; - r11 : pwd_len addr
; - r12 : _buff

%define loop_print_failed           0x8021f85f
%define loop_print_success          0x2198d42f

jmp .start
real_hash dq	                    0xed9822325a6c999e      ; @P3E%3#yY5!#@hM5
init1 dd		                    0xbfe5164c
init2 dd		                    0x64d1ada1
key1 dd			                    0x76ffa4bb
key2 dd			                    0xd8689c54

; Calculate hash
%macro hash 0
	mov rax, 0					; Loop counter (one iter)
    mov cl, byte [r11]          ; pwd_len
    mov rbx, r12                ; _buff
    mov rdx, r10                ; code offset
	; Clean registers
	xor r10, r10
    mov r11, r10
    mov r12, r10
    mov r13, r10
    mov r14, r10
	mov r15, r10
	mov r14d, dword [rdx+init1]		; Precedent result
	mov r15d, dword [rdx+init2]		; Precedent result
	.hash_loop:
	; First char
	mov r10b, [rbx+rax]
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
	xor r10d, dword [rdx+key1]
	; Clear tmp registers
	xor r11, r11
	mov r12, r11
	mov r13, r11

	; Second char
	mov r9b, [rbx+rax+1]
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
	xor r9d, dword [rdx+key2]
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
	cmp al, cl
	jne .hash_loop

	; Merge results
	shl r14, 32
	add r14, r15
%endmacro

.start:
; Check password
hash
; Compare hash
cmp r14, [rdx+real_hash]
mov rbx, loop_print_success
mov rcx, loop_print_failed
cmove r15d, ebx
cmovne r15d, ecx
; Reset rcx
xor rcx, rcx
