BITS 64
%use altreg

; Input :
; - r10 : code offset
; - r11 : pwd_len addr
; - r12 : _buff

%define loop_print_failed           0x8021f85f
%define loop_print_success          0x2198d42f

jmp .start
real_hash dq	                    0xb19b027114644e82      ; @P3E%3#yY5!#@hM5
init1 dq		                    0xded80c612eaed1e6
init2 dq		                    0x1d66514734a9cb36
key1 dq			                    0x4613031ad0de432c
key2 dq			                    0xbc66534f00e74f08

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
	mov r14, [rdx+init1]		; Precedent result
	mov r15, [rdx+init2]		; Precedent result
	.hash_loop:
	; First char
	mov r10b, [rbx+rax]		; Get one char
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
    ; Shift 2
	shl r11, 8
	shl r12, 8*3
	shl r13, 8*5
	; Extend output 2
	add r10, r11
	add r10, r12
	add r10, r13
	; Add final byte
	mov r11b, r10b
	shl r11, 8*3
	add r10, r11
	; Mix
	xor r10, [rdx+key1]
	; Clear tmp registers
	xor r11, r11
	mov r12, r11
	mov r13, r11

	; Second char
	mov r9b, [rbx+rax+1]	; Get one char+1
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
    ; Shift 2
	shl r11, 8
	shl r12, 8*3
	shl r13, 8*5
	; Extend output 2
	add r9, r11
	add r9, r12
	add r9, r13
	; Add final byte
	mov r11b, r9b
	shl r11, 8*3
	add r9, r11
	; Mix
	xor r9, [rdx+key2]
	; Clear tmp registers
	xor r11, r11
	mov r12, r11
	mov r13, r11

	; Mix with previous result
	add r9, r14
	add r10, r15
	mov r14, r9
	mov r15, r10
	; Clean results
	xor r9, r9
	xor r10, r10

	; Loop control (one iter)
	inc rax
	cmp al, cl
	jne .hash_loop

	; Merge results
	xor r14, r15
	xor r15, r15
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
