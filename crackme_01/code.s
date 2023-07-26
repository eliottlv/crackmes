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
%define loop_exit_1v1               0xdd2d38da
%define loop_exit_1v2               0x8dff7d3f
%define loop_dbg_found              0x1221a352
%define loop_fake_dbg_found         0xc87d5f58
%define loop_failed                 0x72605214
%define loop_fake_failed            0x02fe318b
%define loop_success                0xa5db20db
%define loop_fake_sucess            0xbf791a66
%define loop_print_failed           0x76fd5ede
%define loop_print_success          0x50a4d741

; Decrypt code (code, key, size)
%macro decrypt_code 3
    .decrypt_code_start_%1:
    mov rax, [%1+rcx]
    mov rbx, [%2]
    xor rax, rbx
    mov [%1+rcx], rax
    add rcx, 8
    cmp rcx, %3
    jne .decrypt_code_start_%1
    xor r2, r2
    mov r5, r2
    mov rcx, r2
%endmacro

; Calculate hash
%macro hash 0
	mov rax, 0					; Loop counter (one iter)
	mov cl, byte [pwd_len]		; String size
	; Clean registers
	xor r10, r10
    mov r11, r10
    mov r12, r10
    mov r13, r10
    mov r14, r10
	mov r15, r10
	mov r14d, dword [init1]		; Precedent result
	mov r15d, dword [init2]		; Precedent result
	.hash_loop:
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
	cmp al, cl
	jne .hash_loop

	; Merge results
	shl r14, 32
	add r14, r15
%endmacro

section .bss
    _buff:
    buff resb       256         ; Reserver 256 octets
    buff_len equ    $-buff
    pwd_len resb    1

section .data
    ;callkey_dbg dq                      0x3cd80dab4e222151, 0x4eff84ccf057ead5
    ;check_failed_callkey dq             0x99e0251e08e0e7b2
    ;check_succes_callkey dq             0x4fd7fe1f8d6e5ea2
    real_hash dq	                    0xed9822325a6c999e      ; @P3E%3#yY5!#@hM5
    init1 dd		                    0xbfe5164c
	init2 dd		                    0x64d1ada1
	key1 dd			                    0x76ffa4bb
	key2 dd			                    0xd8689c54
    ; Keys for code encryption
    key_c1 dq 0x7b54fdb582d167d3
    key_c2 dq 0xce4bef69b68ecef2
    key_c3 dq 0xb6be1e3ad352da24
    key_c4 dq 0xa621f9e48cf8c2cf
    key_c5 dq 0xfe4f971e90b2f830
    key_c6 dq 0xd616675b49d1410b
    key_c7 dq 0x6052204391370258
    key_c8 dq 0x407bc358e5091036
    key_c9 dq 0x67a19aafabf62d84
    key_c10 dq 0x01eb91ec1618e6d8
    key_c11 dq 0xfdd73e47389c422d

section .code exec write align=8
    _code:
    ; nasm -f bin -o tmp.o crackme_01/dbg_check_v1.s; ./asmcrypt.py tmp.o
    .dbg_check_v1:
    dq 0x7bbf3d4aca11569b
    dq 0xba1c3d4aca31b69b
    dq 0x48571615863a6233
    dq 0x7e5bf87501999c38
    dq 0xe26544a7a3723568
    dq 0x7410fd4d01999c90
    dq 0xebc404f18d959c96
    len_code_1 equ $-.dbg_check_v1
    jmp _start.main_loop-3

    ; nasm -f bin -o tmp.o crackme_01/dbg_check_v2.s; ./asmcrypt.py tmp.o
    .dbg_check_v2:
    dq 0x38d15f695d4effba
    dq 0xdc6a4c3b0d8bc122
    dq 0x36c8a792f517ff4b
    dq 0x8a44ab92f3818af2
    dq 0x5edb7ff9261e5e0b
    len_code_2 equ $-.dbg_check_v2
    jmp _start.main_loop-3

    ; nasm -f bin -o tmp.o crackme_01/print_dbg_found.s; ./asmcrypt.py tmp.o
    .print_dbg_found:
    dq 0x70cbf805861dc2cf
    dq 0xc17c31cad9271712
    dq 0x3ea6a05da658eae9
    dq 0xb6be1cf8521bcb0e
    dq 0xa07c9d7303db9624
    dq 0x3ff6e80b9b815368
    dq 0x8d357832e7d9bcd3
    dq 0x3efee00bb59d0942
    dq 0x7a4156323d93bcd3
    dq 0xf672e172f76e5264
    dq 0x3ff6e80b9b76eeac
    dq 0xfe7697732bdb93d3
    dq 0xd3537442c3b91a15
    dq 0xb702aa273895536c
    dq 0x5d7ee172c303638b
    dq 0x0c204875b16037cb
    dq 0xe1f510d1d352da26
    dq 0xfe4ef5dc5a1a6023
    dq 0x3ff21b352ab96167
    dq 0xfb7ae17217ad92e5
    dq 0x774156fb2c1a3e15
    dq 0x15eca47bc5ab596c
    dq 0x3b4163056813c805
    dq 0x4dfa117f2917d561
    dq 0x262e8eaa1f16d56d
    len_code_3 equ $-.print_dbg_found
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/print_prompt.s; ./asmcrypt.py tmp.o
    .print_prompt:
    dq 0xa0264f36ca1ecc24
    dq 0xb0a678212bd4acf1
    dq 0xea21f9e48e3a4386
    dq 0x2f6df5260fb11246
    dq 0xc0d670ac7ac98a1c
    dq 0x7547c26feaf0f644
    dq 0xc0d671a472c9a400
    dq 0x2e61351bc4f02c0e
    dq 0x92a9b92873b0e6f3
    dq 0xefd670ac7ac98aeb
    dq 0x6610b12c05b13a46
    dq 0x3707c8eeea10cc24
    dq 0xada9e7fa673f4b87
    dq 0x5ad4da1767383d87
    dq 0x1c6b327eb3496ff8
    dq 0xf1e6f70f8cf8c2cd
    dq 0x49ca1f6dc42943b5
    dq 0x2f6dfceb7513f47e
    dq 0xebe506ac48078a0e
    dq 0x67deb12573b026fe
    dq 0x3f1043a580014187
    dq 0x13ea794637b9398c
    dq 0x5d65f6a176bdcd8a
    dq 0x36b1697440bccd86
    len_code_4 equ $-.print_prompt
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/print_success.s; ./asmcrypt.py tmp.o
    .print_success:
    dq 0xab3b3461c3b4f4db
    dq 0x7f06976dc2b84711
    dq 0x2ec6db1e90b2faf2
    dq 0xb69c1e529a707b79
    dq 0xcac4f1e919fa0e01
    dq 0x98804478ab399e38
    dq 0x108ef1e918f20601
    dq 0xda731f5e5c4db038
    dq 0xb66ba396d07e0778
    dq 0x06c6dee919fa0e01
    dq 0xeda4572fd87a7179
    dq 0x39c6df98e2ec2409
    dq 0x9627908f93ecd9db
    dq 0x13a457e1d89ba46e
    dq 0xfe4d2dc6da0ae33b
    dq 0x71e875da8659f830
    dq 0x13a47197d8630308
    dq 0x5d67d478502f781b
    dq 0xb68e1e5295bd01db
    dq 0x1a7edada6ffa3ccf
    dq 0x7d0756e1d8730778
    dq 0xaeeb405f2af3f2c9
    dq 0xf10a4a947bc84371
    dq 0xf1066c5a9ff70275
    dq 0x6edf078e00223474
    len_code_5 equ $-.print_success
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/print_failed.s; ./asmcrypt.py tmp.o
    .print_failed:
    dq 0x27685e5d4e194de0
    dq 0x575f26f2ea90c42c
    dq 0x069f2b5b49d143c9
    dq 0x9ec5ee174313c242
    dq 0xe29d01acc099b73a
    dq 0xb0d9b43d725a2703
    dq 0x38d701acc191bf3a
    dq 0xf22aef1b852e0903
    dq 0x9e3253d3091dbe43
    dq 0x2e9f2eacc099b73a
    dq 0xc5fda76a0119c842
    dq 0xfafda0d201a6ae2b
    dq 0xac59778374156d1d
    dq 0x3dfda7a4013b2f9e
    dq 0x11bcee8bfa671beb
    dq 0xe60d8c5b49d143b1
    dq 0x8d92711910e7c91b
    dq 0x3df0ee13b2f8aadb
    dq 0x5daf5a0f898bc9ec
    dq 0x9ed7ee174cdeb8e0
    dq 0x32272a9fb69985f4
    dq 0x555ea6a40110be43
    dq 0xa0eb3985f3904bf2
    dq 0xd953ba76710bfa4a
    dq 0xd95f9c1f4694bb4e
    dq 0x4686f7cbd9418d4f
    len_code_6 equ $-.print_failed
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/exit_1v2.s; ./asmcrypt.py tmp.o
    .exit_1v2:
    dq 0xa75d68437af73310
    dq 0x195158d3490e4aab
    dq 0x60b91ae295dc415d
    dq 0x28522043ab8f91cd
    dq 0x60529f836e7fc2a7
    dq 0x29572f846e7f0258
    dq 0x585d46b17af34757
    dq 0xf0c2e30b9e7fc386
    len_code_7 equ $-.exit_1v2

    ; nasm -f bin -o tmp.o crackme_01/exit_1v1.s; ./asmcrypt.py tmp.o
    .exit_1v1:
    dq 0x4f9026d1a8ed217b
    dq 0xab944a14d55ef494
    dq 0x091ad7b542b02e18
    dq 0x7690c99d15e2d5c9
    dq 0x0978d69f2b8fd95f
    dq 0x2912ab5e0e0bf4f7
    dq 0xa69023d1a9914a16
    dq 0x0908e8cf11b8019c
    dq 0x84848abc3440d4c9
    dq 0x913207a7acedc17f
    dq 0x457412b321f659d2
    dq 0xd0eb53c8759980a6
    len_code_8 equ $-.exit_1v1

    ; nasm -f bin -o tmp.o crackme_01/exit_0.s; ./asmcrypt.py tmp.o
    .exit_0:
    dq 0x2a4e34fb40091ccc
    dq 0x01c72b90400ea4cc
    dq 0x078f1f507ca6dff9
    dq 0xf5c01eb4dd8fe1e0
    dq 0x097f37a04026dbcc
    dq 0x0e0dfb841f6068ac
    dq 0xc7dbaf4490e6fe0c
    dq 0x1f42535a2c110433
    dq 0x5e447b5c0c0586d8
    dq 0x67a15917ce9be921
    dq 0xa14192d86338c684
    dq 0x8822d2ad6c7565ec
    dq 0x8822d2af6c756585
    dq 0xf7310aaaa46bc685
    len_code_9 equ $-.exit_0

    ; nasm -f bin -o tmp.o crackme_01/get_pass.s; ./asmcrypt.py tmp.o
    .get_pass:
    dq 0x51cd534dd476f733
    dq 0x22f34b837c64b9b3
    dq 0x120047655a74a224
    dq 0xdb62dd977369e168
    dq 0x3dd3338d0e38ce33
    dq 0x01eb91ecae4639eb
    dq 0xe150fb7d94e9ec33
    dq 0x01eb9153164458d8
    dq 0xb0a0adb070c20dd8
    dq 0x49236ea413178698
    dq 0xbeaab5e89f512e27
    dq 0x9122a0a47a47645e
    len_code_10 equ $-.get_pass
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/check_pass.s; ./asmcrypt.py tmp.o
    .check_pass:
    dq 0xdfe5642ba1025ac6
    dq 0x507681a22ed0afb5
    dq 0x618348b89c2726fc
    dq 0xbcd73e4738249a45
    dq 0x2f5e72a4b1d049a7
    dq 0x749aedce754e7360
    dq 0xb001b70aed150ff9
    dq 0xfdd734f5b3d895a4
    dq 0xfdd73e498217062d
    dq 0xb804b6023b88c869
    dq 0x37177f92b0d996a5
    dq 0x31177f55f35c032b
    dq 0x1e167f4ef55c0322
    dq 0x18167f57dc5d0335
    dq 0xb8353f02e29d0725
    dq 0xfdd72cd50bd8a82c
    dq 0xb00bb70ae3ad0f2d
    dq 0xb8d63d0bb2d89fa4
    dq 0x305f7b8bb0d989a5
    dq 0xfe1cfe062955826c
    dq 0xfa1afe062a50826c
    dq 0xed33ff06207f836c
    dq 0xb80e3f023079836c
    dq 0x77e47aae39d9a32c
    dq 0xb00c0f0a389c423b
    dq 0x0ce67b9ab1d19ea4
    dq 0x7492f0ce7d667368
    dq 0xb5050f0af1ad0ffa
    dq 0x0289bb48f0a482d2
    dq 0xfc9a1ea1f9d5bdd2
    dq 0xfdd73e458aa70ed3
    dq 0xafc387e2e3bc9996
    dq 0xf293c50337d8304d
    dq 0x6d47ae8e09d4bb68
    len_code_11 equ $-.check_pass
    jmp _start.main_loop

section .text
global _start
_start:
    ; Random start selector
    ; Register r15 is used to store the switch evaluated data
    rdrand r14
    rdrand r15

    ; cmp r15, r14
    ; js .dbg_check_v1
    ; jns .dbg_check_v2

    ; .dbg_check_v1:
    ; decrypt_code _code.dbg_check_v1, key_c1, len_code_1
    ; jmp _code.dbg_check_v1

    ; .dbg_check_v2:
    ; decrypt_code _code.dbg_check_v2, key_c2, len_code_2
    ; jmp _code.dbg_check_v2

    mov r15d, loop_print_prompt

    ;;;;;;;;;;;;;;;
    ;;;;;; Main Loop
    ;;;;;;;;;;;;;;;

    xor rcx, rcx
    .main_loop:
    ; Switch statement for CFG flattening
    ; Some switch cases are not reachable. They're just here to mislead the decompiler.
    ; r15d is user to check the cases.
    cmp r15d, loop_exit_1v1
    je .exit_1v1
    cmp r15d, loop_failed
    je .print_failed
    cmp r15d, loop_fake_get_pass
    je .get_pass
    cmp r15d, loop_check_pass
    je .check_pass
    cmp r15d, loop_success
    je .print_success
    cmp r15d, loop_print_prompt
    je .print_prompt
    cmp r15d, loop_fake_print_prompt
    je .print_prompt
    cmp r15d, loop_fake_failed
    je .print_failed
    cmp r15d, loop_dbg_found
    je .print_dbg_found
    cmp r15d, loop_get_pass
    je .get_pass
    cmp r15d, loop_print_failed
    je .print_failed
    cmp r15d, loop_fake_sucess
    je .print_success
    cmp r15d, loop_fake_dbg_found
    je .print_dbg_found
    cmp r15d, loop_exit_0
    je .exit_0
    cmp r15d, loop_print_success
    je .print_success
    cmp r15d, loop_fake_check_pass
    je .check_pass
    cmp r15d, loop_exit_1v2
    je .exit_1v2

    ; Print debugger found and exit 2
    .print_dbg_found:
    mov r10, _code.print_dbg_found
    cmp byte [_code.print_dbg_found], 0xcf     ; Don't decrypt a second time
    jne _code.print_dbg_found
    decrypt_code _code.print_dbg_found, key_c3, len_code_3
    jmp _code.print_dbg_found

    .print_prompt:
    ; Print prompt
    mov r10, _code.print_prompt
    cmp byte [_code.print_prompt], 0x24     ; Don't decrypt a second time
    jne _code.print_prompt
    decrypt_code _code.print_prompt, key_c4, len_code_4
    jmp _code.print_prompt

    .get_pass:
    ; Get usefull addresses
    mov r10, buff
    mov r11, buff_len
    mov r12, pwd_len
    ; Decrypt code
    cmp byte [_code.get_pass], 0x33     ; Don't decrypt a second time
    jne _code.get_pass
    decrypt_code _code.get_pass, key_c10, len_code_10
    jmp _code.get_pass

    .check_pass:
    ; Get usefull addresses
    mov r10, _code.check_pass
    mov r11, pwd_len
    mov r12, _buff
    ; Check password
    cmp byte [_code.check_pass], 0xc6     ; Don't decrypt a second time
    jne _code.check_pass
    decrypt_code _code.check_pass, key_c11, len_code_11
    jmp _code.check_pass

    .print_success:
    mov r10, _code.print_success
    cmp byte [_code.print_success], 0xdb     ; Don't decrypt a second time
    jne _code.print_success
    decrypt_code _code.print_success, key_c5, len_code_5
    jmp _code.print_success

    .print_failed:
    mov r10, _code.print_failed
    cmp byte [_code.print_failed], 0xe0     ; Don't decrypt a second time
    jne _code.print_failed
    decrypt_code _code.print_failed, key_c6, len_code_6
    jmp _code.print_failed

    .exit_0:
    cmp byte [_code.exit_0], 0xcc     ; Don't decrypt a second time
    jne _code.exit_0
    decrypt_code _code.exit_0, key_c9, len_code_9
    jmp _code.exit_0

    .exit_1v1:
    cmp byte [_code.exit_1v1], 0x7b     ; Don't decrypt a second time
    jne _code.exit_1v1
    decrypt_code _code.exit_1v1, key_c8, len_code_8
    jmp _code.exit_1v1

    .exit_1v2:
    cmp byte [_code.exit_1v2], 0x10     ; Don't decrypt a second time
    jne _code.exit_1v2
    decrypt_code _code.exit_1v2, key_c7, len_code_7
    jmp _code.exit_1v2

    ; Calculate call address
    ; mov rax, 0x4fd7fe1f8d2e4ed3     ; Encrypted address .main_loop
    ; mov rbx, [check_succes_callkey]
    ; xor rax, rbx
    ; jmp rax
