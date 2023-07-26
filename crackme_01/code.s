BITS 64
%use altreg

; Constants for CFG flattening.
%define loop_print_prompt           0xa8c20c6e
%define loop_get_pass               0xc39fa982
%define loop_check_pass             0x10f29a27
%define loop_exit_0                 0x6f444add
%define loop_exit_1v1               0xd088ccc3
%define loop_exit_1v2               0x4e788b25
%define loop_dbg_found              0xcd8699c1
%define loop_print_failed           0x8021f85f
%define loop_print_success          0x2198d42f

; Fake constants for CFG flattening.
%define loop_fake_dbg_found         0x560fb610
%define loop_fake_sucess            0xd9663563
%define loop_fake_failed            0x60d20f8d
%define loop_fake_check_pass        0xbefdc23a
%define loop_fake_get_pass          0xdc680b7f
%define loop_fake_print_prompt      0x8da5bc2e

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

section .bss
    _buff:
    buff resb       256         ; Reserver 256 octets
    buff_len equ    $-buff
    pwd_len resb    1

section .data
    ; Keys for code encryption
    key_c1 dq 0xf57a71262bce4c96
    key_c2 dq 0xf63bdaf6fbaf66ad
    key_c3 dq 0xbf9306688357c8dc
    key_c4 dq 0xaf4ae128669f74e9
    key_c5 dq 0xf9709892ee9cc1ac
    key_c6 dq 0x5b18681d3977cc7b
    key_c7 dq 0x6052204391370258
    key_c8 dq 0x407bc358e5091036
    key_c9 dq 0x67a19aafabf62d84
    key_c10 dq 0x3eba7469d35249ed
    key_c11 dq 0x0cd8b0ce55b43b3c

section .code exec write align=8
    _code:
    ; nasm -f bin -o tmp.o crackme_01/dbg_check_v1.s; ./asmcrypt.py tmp.o
    .dbg_check_v1:
    dq 0xf591b1d9630e7dde
    dq 0x3432b1d9632e9dde
    dq 0xc6799a862f254976
    dq 0xf07574e6a886b77d
    dq 0xf914c8ebad578d2d
    dq 0xfa3e71dea886e454
    dq 0x65ea8862248ab7d3
    len_code_1 equ $-.dbg_check_v1
    jmp _start.main_loop-3

    ; nasm -f bin -o tmp.o crackme_01/dbg_check_v2.s; ./asmcrypt.py tmp.o
    .dbg_check_v2:
    dq 0x00a16af6106f57e5
    dq 0x3bbd433740aa697d
    dq 0x0eb8925e39a30814
    dq 0xb2349e0dbea022ad
    dq 0x66ab4a666b3ff654
    len_code_2 equ $-.dbg_check_v2
    jmp _start.main_loop-3

    ; nasm -f bin -o tmp.o crackme_01/print_dbg_found.s; ./asmcrypt.py tmp.o
    .print_dbg_found:
    dq 0x79e6e057d618d037
    dq 0xc8512998892205ea
    dq 0x378bb80ff65df811
    dq 0xbf9304aa021ed9f6
    dq 0xa951852153de84dc
    dq 0x36dbf059cb844190
    dq 0x84186060b7dcae2b
    dq 0x37d3f859e5981bba
    dq 0x736c4e606d96ae2b
    dq 0xff5ff920a76b409c
    dq 0x36dbf059cb73fc54
    dq 0xf75b8f217bde812b
    dq 0xda7e6c1093bc08ed
    dq 0xbe2fb27568904194
    dq 0x5453f92093067173
    dq 0x050d5027e1652533
    dq 0xe8d808838357c8de
    dq 0xf763ed8e0a1f72db
    dq 0x36df03677abc739f
    dq 0xf257f92047a8801d
    dq 0x7e6c4ea97c1f2ced
    dq 0x2652bc2995ae4b94
    dq 0xf1eb8d4d3816055a
    dq 0x44d7092d7912c799
    dq 0x2f0396f84f13c795
    len_code_3 equ $-.print_dbg_found
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/print_prompt.s; ./asmcrypt.py tmp.o
    .print_prompt:
    dq 0xa94d57fa20797a02
    dq 0xb9cd60edc1b31ad7
    dq 0xe34ae128645df5a0
    dq 0x2606edeae5d6a460
    dq 0xc9bd686090ae3c3a
    dq 0x7c2cdaa300974062
    dq 0xc9bd696898ae1226
    dq 0x270a2dd72e979a28
    dq 0x9bc2a1e499d750d5
    dq 0xe6bd686090ae3ccd
    dq 0x6f7ba9e0efd68c60
    dq 0x3e6cd02200777a02
    dq 0xa4c2ff368d58fda1
    dq 0x53bfc2db8d5f8ba1
    dq 0x15002ab2592ed9de
    dq 0xf88defc3669f74eb
    dq 0x40a107a12e4ef593
    dq 0x2606e4279f744258
    dq 0xe28e1e60a2603c28
    dq 0x6eb5a9e999d790d8
    dq 0xa3245b696a66f7a1
    dq 0x6cd548aadddedc2b
    dq 0x540eee6d9cda7bac
    dq 0x3fda71b8aadb7ba0
    len_code_4 equ $-.print_prompt
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/print_success.s; ./asmcrypt.py tmp.o
    .print_success:
    dq 0xac043bedbd9acd47
    dq 0x783998e1bc967e8d
    dq 0x29f9d492ee9cc36e
    dq 0xb1a311dee45e42e5
    dq 0xcdfbfe6567d4379d
    dq 0x9fbf4bf4d517a7a4
    dq 0x17b1fe6566dc3f9d
    dq 0xdd4c10d2226389a4
    dq 0xb154ac1aae503ee4
    dq 0x01f9d16567d4379d
    dq 0xea9b58a3a65448e5
    dq 0x3ef9d0149cc21d95
    dq 0x91189f03edc2e047
    dq 0x149b586da6b59df2
    dq 0xf972224aa424daa7
    dq 0x76d77a56f877c1ac
    dq 0x149b7e1ba64d3a94
    dq 0x5a58dbf42e014187
    dq 0xb1b111deeb933847
    dq 0x1d41d55611d40553
    dq 0x7a38596da65d3ee4
    dq 0xd8e84cbd54ddcb55
    dq 0xf635f7d6a4417aed
    dq 0xf63963d6e1d93be9
    dq 0x69e008027e0c0de8
    len_code_5 equ $-.print_success
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/print_failed.s; ./asmcrypt.py tmp.o
    .print_failed:
    dq 0xaa66511b3ebfc090
    dq 0xda5129b49a36495c
    dq 0x8b91241d3977ceb9
    dq 0x13cbe15133b54f32
    dq 0x6f930eeab03f3a4a
    dq 0x3dd7bb7b02fcaa73
    dq 0xb5d90eeab137324a
    dq 0x7f24e05df5888473
    dq 0x133c5c9579bb3333
    dq 0xa39121eab03f3a4a
    dq 0x48f3a82c71bf4532
    dq 0x77f3af947100235b
    dq 0x215778c504b3e06d
    dq 0xb0f3a8e2719da2ee
    dq 0x9cb2e1cd8ac1969b
    dq 0x6b03831d3977cec1
    dq 0x009c7e5f6041446b
    dq 0xb0fee155c25e27ab
    dq 0xd0a15549f92d449c
    dq 0x13d9e1513c783590
    dq 0xbf2925d9c63f0884
    dq 0xd850a9e271b63333
    dq 0xdb3990428336c682
    dq 0x545db895f5b4773a
    dq 0x545193593632363e
    dq 0xcb88f88da9e7003f
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
    dq 0x6e9cb6c8113c5806
    dq 0x1da2ae06b92e1686
    dq 0x2d51a2e09f3e0d11
    dq 0xe4333812b6234e5d
    dq 0x0282d608cb726106
    dq 0x3eba74696b0c96de
    dq 0xde011ef851a34306
    dq 0x3eba74d6d30ef7ed
    dq 0x8ff14835b588a2ed
    dq 0x76728b21d65d29ad
    dq 0x81fb506d5a1b8112
    dq 0xae734521c3a0d3ca
    len_code_10 equ $-.get_pass
    jmp _start.main_loop

    ; nasm -f bin -o tmp.o crackme_01/check_pass.s; ./asmcrypt.py tmp.o
    .check_pass:
    dq 0x0ea9a4aa1b3613d7
    dq 0x00b99e6084528aa7
    dq 0x5d9f84679e82e5e4
    dq 0x0fc260101698265a
    dq 0x5f97b0291abc7d2f
    dq 0x4dd8b0ce550c875a
    dq 0xde51fc2ddcf830b6
    dq 0x8595634718660a71
    dq 0x410e3983803d76e8
    dq 0x0cd8ba7cdef8ecb5
    dq 0x0cd8b0dcef3f773c
    dq 0x490b388b56a0b178
    dq 0xc618f11bddf1efb4
    dq 0xc018f1dc9e747a3a
    dq 0xef19f1c798747a33
    dq 0xe919f1deb1757a24
    dq 0x493ab18b8fb57e34
    dq 0xcd91b82d94fdd13d
    dq 0x0d95982b94fd23d8
    dq 0x4932b183b7b576e6
    dq 0x0d95a82d94fde8b4
    dq 0x0cd8b0d4c78777e6
    dq 0x85956c47186f0a71
    dq 0x849db1cd193e7fe1
    dq 0x4d15388b993c7ef7
    dq 0x4ddb7b0e14a5f2fc
    dq 0x4ddf7d0e14a6f7fc
    dq 0x4dc8540f14acd8fd
    dq 0x0d9d69cf10bcdefd
    dq 0x043b7187bcb57edd
    dq 0x243d71874d50fa75
    dq 0x0d9551cf186d3a71
    dq 0x143b71879e3c7ed5
    dq 0x0cfa3afd196d3a71
    dq 0xd051fd1564f93b3c
    dq 0x0d9541cf1869b271
    dq 0x410f39839b3d76c6
    dq 0xcc27f81c64f9f20d
    dq 0xf3274feed0bbf304
    dq 0x37944fff184a0a71
    dq 0xd8f70bce55b4398e
    dq 0x485891360a0d1aa4
    dq 0x4421f5c1114f7f33
    dq 0x9c48205ec524f20d
    len_code_11 equ $-.check_pass
    jmp _start.main_loop

section .text
global _start
_start:
    ; Random start selector
    ; Register r15 is used to store the switch evaluated data
    rdrand r14
    rdrand r15

    cmp r15, r14
    js .dbg_check_v1
    jns .dbg_check_v2

    .dbg_check_v1:
    decrypt_code _code.dbg_check_v1, key_c1, len_code_1
    jmp _code.dbg_check_v1

    .dbg_check_v2:
    decrypt_code _code.dbg_check_v2, key_c2, len_code_2
    jmp _code.dbg_check_v2

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
    cmp r15d, loop_fake_get_pass
    je .get_pass
    cmp r15d, loop_check_pass
    je .check_pass+10
    cmp r15d, loop_print_prompt
    je .print_prompt+16
    cmp r15d, loop_fake_print_prompt
    je .print_prompt
    cmp r15d, loop_fake_failed
    je .print_failed
    cmp r15d, loop_dbg_found
    je .print_dbg_found+22
    cmp r15d, loop_get_pass
    je .get_pass+19
    cmp r15d, loop_print_failed
    je .print_failed+15
    cmp r15d, loop_fake_sucess
    je .print_success
    cmp r15d, loop_fake_dbg_found
    je .print_dbg_found
    cmp r15d, loop_exit_0
    je .exit_0
    cmp r15d, loop_print_success
    je .print_success+30
    cmp r15d, loop_fake_check_pass
    je .check_pass
    cmp r15d, loop_exit_1v2
    je .exit_1v2

    ; Print debugger found and exit 2
    .print_dbg_found:
    db 0x64,0x5c,0xf9,0xa1,0x9e,0xb4,0xb2,0x14,0x7f,0xa9,0xeb,0x7b,0x3b,0x0e,0x57,0xea,0xd5,0x99,0xf8,0x87,0x09,0xa5
    mov r10, _code.print_dbg_found
    cmp byte [_code.print_dbg_found], 0x37     ; Don't decrypt a second time
    jne _code.print_dbg_found
    decrypt_code _code.print_dbg_found, key_c3, len_code_3
    jmp _code.print_dbg_found

    ; Print prompt
    .print_prompt:
    db 0x15,0x72,0xdf,0xfc,0x49,0xf8,0x3e,0x2e,0xad,0xf4,0xd8,0x1e,0xe2,0x21,0xae,0x27
    mov r10, _code.print_prompt
    cmp byte [_code.print_prompt], 0x02     ; Don't decrypt a second time
    jne _code.print_prompt
    decrypt_code _code.print_prompt, key_c4, len_code_4
    jmp _code.print_prompt

    ; Get password
    .get_pass:
    db 0x45,0x1d,0xe3,0x00,0x1e,0x94,0xb9,0xbc,0xc0,0x50,0x0f,0x19,0x75,0x8f,0x35,0x06,0xd7,0x51,0x6e
    ; Get usefull addresses
    mov r10, buff
    mov r11, buff_len
    mov r12, pwd_len
    ; Decrypt code
    cmp byte [_code.get_pass], 0x06     ; Don't decrypt a second time
    jne _code.get_pass
    decrypt_code _code.get_pass, key_c10, len_code_10
    jmp _code.get_pass

    ; Check password with hashing
    .check_pass:
    db 0xcc,0x27,0xc7,0x51,0x28,0xe5,0x94,0x9e,0xde,0xaf
    ; Get usefull addresses
    mov r10, _code.check_pass
    mov r11, pwd_len
    mov r12, _buff
    ; Check password
    cmp byte [_code.check_pass], 0xd7     ; Don't decrypt a second time
    jne _code.check_pass
    decrypt_code _code.check_pass, key_c11, len_code_11
    jmp _code.check_pass

    .print_success:
    db 0xd0,0x47,0xad,0xbf,0xf2,0xdf,0xc6,0xb0,0x75,0x99,0xaf,0x8e,0x87,0xb8,0xc2,0x75,0xec,0xfb,0x41,0x3f,0x2c,0xc1,0x35,0xe4,0x06,0xad,0x6a,0x54,0xca,0x1c
    mov r10, _code.print_success
    cmp byte [_code.print_success], 0x47     ; Don't decrypt a second time
    jne _code.print_success
    decrypt_code _code.print_success, key_c5, len_code_5
    jmp _code.print_success

    .print_failed:
    db 0x60,0x3e,0x89,0x40,0x57,0x57,0xa2,0x6a,0x56,0xda,0x3e,0xfe,0x20,0x13,0xfb
    mov r10, _code.print_failed
    cmp byte [_code.print_failed], 0x90     ; Don't decrypt a second time
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
    db 0xde,0x72,0x66,0x17,0xd2,0x4c,0xb6,0x7d,0xfb,0xdb,0xff,0xbe,0x50,0xe7,0x32,0xe6,0xe6,0x7c,0x18

    .exit_1v2:
    cmp byte [_code.exit_1v2], 0x10     ; Don't decrypt a second time
    jne _code.exit_1v2
    decrypt_code _code.exit_1v2, key_c7, len_code_7
    jmp _code.exit_1v2
    db 0x28,0xd9,0xc6,0x20,0x0d,0x5d,0xb7,0x61,0x6c,0x22,0x3f,0xb3,0x61,0x76,0xa4,0xdc
