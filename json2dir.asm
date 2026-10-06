; json2dir: create the directory tree a JSON document describes, in the current directory.
; Implements RFC J2D-1. x86-64 Linux, raw syscalls only, no libc.
; Build: jwasm -q -bin -Fo=json2dir json2dir.asm   (the ELF header is written by hand below)
;
; The document is parsed twice by the same recursive parser: pass 1 (rbx=0) only
; validates, pass 2 (rbx=1) creates the entries. Nothing is written unless pass 1 succeeds.
;
; Global registers: r12 = input cursor, r13 = input end, r14 = name buffer,
;                   r15 = value buffer, rbx = apply flag.

        .x64
        option casemap:none
        option prologue:none
        option epilogue:none

BASE            equ 400000h
MAXDEPTH        equ 512

SYS_READ        equ 0
SYS_WRITE       equ 1
SYS_CLOSE       equ 3
SYS_BRK         equ 12
SYS_FCHMOD      equ 91
SYS_UMASK       equ 95
SYS_EXIT_GROUP  equ 231
SYS_OPENAT      equ 257
SYS_MKDIRAT     equ 258
SYS_NEWFSTATAT  equ 262
SYS_UNLINKAT    equ 263
SYS_SYMLINKAT   equ 266

AT_FDCWD        equ -100
AT_SYMLINK_NOFOLLOW equ 100h
O_WRONLY        equ 1
O_CREAT         equ 40h
O_EXCL          equ 80h
O_DIRECTORY     equ 10000h
O_NOFOLLOW      equ 20000h
O_CLOEXEC       equ 80000h
S_IFMT          equ 0F000h
S_IFDIR         equ 4000h
ENOENT          equ 2
EINTR           equ 4

FAIL    macro msg
        lea rsi, msg
        mov edx, sizeof msg
        jmp die
        endm

_TEXT   segment para use64 public 'CODE'

;------------------------------------------------------------------ ELF64 header
ehdr    db 7Fh, 'E', 'L', 'F', 2, 1, 1, 0       ; 64-bit, little endian, SysV
        dq 0
        dw 2                                    ; ET_EXEC
        dw 3Eh                                  ; x86-64
        dd 1
        dq BASE + (_start - ehdr)               ; entry point
        dq phdr - ehdr                          ; program header offset
        dq 0                                    ; no section headers
        dd 0
        dw 64, 56, 1, 0, 0, 0
phdr    dd 1, 7                                 ; PT_LOAD, RWX
        dq 0, BASE, BASE                        ; file offset, vaddr, paddr
        dq fileend - ehdr                       ; file size
        dq fileend - ehdr                       ; memory size
        dq 1000h

;------------------------------------------------------------------ data
msg_usage   db "usage: json2dir < document.json", 10
msg_read    db "json2dir: cannot read standard input", 10
msg_mem     db "json2dir: out of memory", 10
msg_utf8    db "json2dir: input is not valid UTF-8", 10
msg_json    db "json2dir: input is not a valid json2dir document", 10
msg_root    db "json2dir: the root of the document must be an object", 10
msg_name    db "json2dir: invalid name", 10
msg_array   db "json2dir: an array must be [", 22h, "link", 22h, ", target] or [", 22h, "script", 22h, ", content]", 10
msg_value   db "json2dir: numbers, booleans and null are not allowed", 10
msg_surr    db "json2dir: string contains an unpaired surrogate", 10
msg_depth   db "json2dir: document is nested too deeply", 10
msg_linknul db "json2dir: a link target cannot contain NUL", 10
msg_inway   db "json2dir: a directory is in the way", 10
msg_fs      db "json2dir: file system operation failed", 10

        align 8
docstart dq 0
umaskval dq 0
statbuf  db 144 dup (0)

;------------------------------------------------------------------ entry
_start:
        mov rax, qword ptr [rsp]                ; argc
        cmp rax, 1
        je  args_ok
        mov edi, 2
        lea rsi, msg_usage
        mov edx, sizeof msg_usage
        mov eax, SYS_WRITE
        syscall
        mov edi, 2
        mov eax, SYS_EXIT_GROUP
        syscall
args_ok:
        ; umask: read it by setting it to 0 and restoring
        xor edi, edi
        mov eax, SYS_UMASK
        syscall
        mov qword ptr umaskval, rax
        mov edi, eax
        mov eax, SYS_UMASK
        syscall

        ; read all of stdin into a buffer grown with brk
        xor edi, edi
        mov eax, SYS_BRK
        syscall
        mov r12, rax                            ; buffer start
        mov r13, rax                            ; data end
        mov rbp, rax                            ; capacity end
read_loop:
        cmp r13, rbp
        jb  do_read
        mov rdi, rbp
        sub rdi, r12
        add rdi, 65536
        add rdi, rbp                            ; new end = cap + used + 64K
        mov eax, SYS_BRK
        syscall
        cmp rax, rdi
        jb  fail_mem
        mov rbp, rax
do_read:
        xor edi, edi
        mov rsi, r13
        mov rdx, rbp
        sub rdx, r13
        xor eax, eax                            ; SYS_READ
        syscall
        cmp rax, -EINTR
        je  do_read
        test rax, rax
        js  fail_read
        jz  read_done
        add r13, rax
        jmp read_loop
read_done:
        ; name and value buffers: each can hold any decoded string + NUL
        mov rcx, r13
        sub rcx, r12
        add rcx, 64
        lea r14, [r13 + 16]
        lea r15, [r14 + rcx]
        lea rdi, [r15 + rcx]
        cmp rdi, rbp
        jbe bufs_ok
        mov eax, SYS_BRK
        syscall
        cmp rax, rdi
        jb  fail_mem
bufs_ok:
        ; skip a UTF-8 byte order mark
        mov rax, r13
        sub rax, r12
        cmp rax, 3
        jb  no_bom
        cmp byte ptr [r12], 0EFh
        jne no_bom
        cmp byte ptr [r12+1], 0BBh
        jne no_bom
        cmp byte ptr [r12+2], 0BFh
        jne no_bom
        add r12, 3
no_bom:
        call utf8_check
        mov qword ptr docstart, r12
        xor ebx, ebx
        call parse_document                     ; pass 1: validate
        mov r12, qword ptr docstart
        mov ebx, 1
        call parse_document                     ; pass 2: create
        xor edi, edi
        mov eax, SYS_EXIT_GROUP
        syscall

;------------------------------------------------------------------ errors
fail_read:  FAIL msg_read
fail_mem:   FAIL msg_mem
fail_utf8:  FAIL msg_utf8
fail_json:  FAIL msg_json
fail_root:  FAIL msg_root
fail_name:  FAIL msg_name
fail_array: FAIL msg_array
fail_value: FAIL msg_value
fail_surr:  FAIL msg_surr
fail_depth: FAIL msg_depth
fail_linknul: FAIL msg_linknul
fail_inway: FAIL msg_inway
fail_fs:    FAIL msg_fs

die:    ; rsi = message, edx = length
        mov edi, 2
        mov eax, SYS_WRITE
        syscall
        mov edi, 1
        mov eax, SYS_EXIT_GROUP
        syscall

;------------------------------------------------------------------ strict UTF-8 check of [r12, r13)
utf8_check proc
        mov rcx, r12
next:
        cmp rcx, r13
        jae done
        movzx eax, byte ptr [rcx]
        cmp al, 80h
        jb  ascii
        cmp al, 0C2h
        jb  fail_utf8
        mov r8b, 80h                            ; allowed range of the 2nd byte
        mov r9b, 0BFh
        cmp al, 0E0h
        jb  two
        cmp al, 0F0h
        jb  three
        cmp al, 0F5h
        jae fail_utf8
        ; four bytes
        cmp al, 0F0h
        jne @F
        mov r8b, 90h
@@:     cmp al, 0F4h
        jne @F
        mov r9b, 8Fh
@@:     mov rdx, r13
        sub rdx, rcx
        cmp rdx, 4
        jb  fail_utf8
        call second
        mov al, byte ptr [rcx+2]
        call cont
        mov al, byte ptr [rcx+3]
        call cont
        add rcx, 4
        jmp next
three:
        cmp al, 0E0h
        jne @F
        mov r8b, 0A0h
@@:     cmp al, 0EDh
        jne @F
        mov r9b, 9Fh                            ; no surrogates
@@:     mov rdx, r13
        sub rdx, rcx
        cmp rdx, 3
        jb  fail_utf8
        call second
        mov al, byte ptr [rcx+2]
        call cont
        add rcx, 3
        jmp next
two:
        mov rdx, r13
        sub rdx, rcx
        cmp rdx, 2
        jb  fail_utf8
        call second
        add rcx, 2
        jmp next
ascii:
        inc rcx
        jmp next
done:
        ret
second:
        mov al, byte ptr [rcx+1]
        cmp al, r8b
        jb  fail_utf8
        cmp al, r9b
        ja  fail_utf8
        ret
cont:
        and al, 0C0h
        cmp al, 80h
        jne fail_utf8
        ret
utf8_check endp

;------------------------------------------------------------------ parser
skip_ws proc
again:
        cmp r12, r13
        jae done
        mov al, byte ptr [r12]
        cmp al, ' '
        je  sk
        cmp al, 9
        je  sk
        cmp al, 10
        je  sk
        cmp al, 13
        je  sk
done:
        ret
sk:     inc r12
        jmp again
skip_ws endp

; expect the byte in al at the cursor (after whitespace) and consume it
expect proc
        mov dl, al
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], dl
        jne fail_json
        inc r12
        ret
expect endp

parse_document proc
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], '{'
        jne fail_root
        mov rdi, AT_FDCWD
        xor esi, esi
        call parse_object
        call skip_ws
        cmp r12, r13
        jne fail_json
        ret
parse_document endp

; parse_object: r12 at '{', rdi = directory fd, rsi = depth
parse_object proc
        push rbp
        mov rbp, rsp
        sub rsp, 32
        mov qword ptr [rbp-8], rdi              ; dirfd
        mov qword ptr [rbp-16], rsi             ; depth
        cmp rsi, MAXDEPTH
        ja  fail_depth
        inc r12
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], '}'
        jne member
        inc r12
        jmp done
member:
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], '"'
        jne fail_json
        mov rdi, r14
        call parse_string
        call check_name
        mov al, ':'
        call expect
        call skip_ws
        cmp r12, r13
        jae fail_json
        mov al, byte ptr [r12]
        cmp al, '"'
        je  str_member
        cmp al, '{'
        je  obj_member
        cmp al, '['
        je  arr_member
        jmp fail_value

str_member:
        mov rdi, r15
        call parse_string
        test ebx, ebx
        jz  next_member
        mov rdx, rax
        mov rdi, qword ptr [rbp-8]
        xor ecx, ecx
        call make_file
        jmp next_member

arr_member:
        inc r12
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], '"'
        jne fail_array
        mov rdi, r15
        call parse_string
        cmp rax, 4
        jne not_link
        cmp dword ptr [r15], 'knil'             ; "link"
        jne fail_array
        mov qword ptr [rbp-24], 0
        jmp kind_ok
not_link:
        cmp rax, 6
        jne fail_array
        cmp dword ptr [r15], 'ircs'             ; "scri"
        jne fail_array
        cmp word ptr [r15+4], 'tp'              ; "pt"
        jne fail_array
        mov qword ptr [rbp-24], 1
kind_ok:
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], ','
        jne fail_array
        inc r12
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], '"'
        jne fail_array
        mov rdi, r15
        call parse_string
        mov qword ptr [rbp-32], rax             ; payload length
        call skip_ws
        cmp r12, r13
        jae fail_json
        cmp byte ptr [r12], ']'
        jne fail_array
        inc r12
        cmp qword ptr [rbp-24], 0
        jne is_script
        ; link: target must not contain NUL
        mov rcx, qword ptr [rbp-32]
        mov rdi, r15
@@:     test rcx, rcx
        jz  @F
        cmp byte ptr [rdi], 0
        je  fail_linknul
        inc rdi
        dec rcx
        jmp @B
@@:     test ebx, ebx
        jz  next_member
        mov rdi, qword ptr [rbp-8]
        call make_link
        jmp next_member
is_script:
        test ebx, ebx
        jz  next_member
        mov rdx, qword ptr [rbp-32]
        mov rdi, qword ptr [rbp-8]
        mov ecx, 1
        call make_file
        jmp next_member

obj_member:
        mov rax, -1
        test ebx, ebx
        jz  @F
        mov rdi, qword ptr [rbp-8]
        call prep_dir
@@:     mov qword ptr [rbp-24], rax             ; child fd
        mov rdi, rax
        mov rsi, qword ptr [rbp-16]
        inc rsi
        call parse_object
        test ebx, ebx
        jz  next_member
        mov rdi, qword ptr [rbp-24]
        mov eax, SYS_CLOSE
        syscall

next_member:
        call skip_ws
        cmp r12, r13
        jae fail_json
        mov al, byte ptr [r12]
        inc r12
        cmp al, ','
        je  member
        cmp al, '}'
        jne fail_json
done:
        leave
        ret
parse_object endp

; parse_string: r12 at '"', rdi = destination; returns rax = decoded length (NUL appended)
parse_string proc
        inc r12
        mov r8, rdi
next:
        cmp r12, r13
        jae fail_json
        movzx eax, byte ptr [r12]
        inc r12
        cmp al, '"'
        je  done
        cmp al, '\'
        je  escape
        cmp al, 20h
        jb  fail_json
store:
        mov byte ptr [rdi], al
        inc rdi
        jmp next
escape:
        cmp r12, r13
        jae fail_json
        movzx eax, byte ptr [r12]
        inc r12
        cmp al, '"'
        je  store
        cmp al, '\'
        je  store
        cmp al, '/'
        je  store
        mov dl, 8
        cmp al, 'b'
        je  store_dl
        mov dl, 0Ch
        cmp al, 'f'
        je  store_dl
        mov dl, 0Ah
        cmp al, 'n'
        je  store_dl
        mov dl, 0Dh
        cmp al, 'r'
        je  store_dl
        mov dl, 9
        cmp al, 't'
        je  store_dl
        cmp al, 'u'
        jne fail_json
        call hex4
        cmp eax, 0D800h
        jb  encode
        cmp eax, 0DC00h
        jb  hisurr
        cmp eax, 0E000h
        jb  fail_surr
        jmp encode
hisurr:
        mov r9d, eax
        mov rdx, r13
        sub rdx, r12
        cmp rdx, 2
        jb  fail_surr
        cmp byte ptr [r12], '\'
        jne fail_surr
        cmp byte ptr [r12+1], 'u'
        jne fail_surr
        add r12, 2
        call hex4
        cmp eax, 0DC00h
        jb  fail_surr
        cmp eax, 0E000h
        jae fail_surr
        sub eax, 0DC00h
        sub r9d, 0D800h
        shl r9d, 10
        add eax, r9d
        add eax, 10000h
encode:
        cmp eax, 80h
        jb  store
        cmp eax, 800h
        jb  enc2
        cmp eax, 10000h
        jb  enc3
        mov edx, eax                            ; 4 bytes
        shr edx, 18
        or  dl, 0F0h
        mov byte ptr [rdi], dl
        mov edx, eax
        shr edx, 12
        and dl, 3Fh
        or  dl, 80h
        mov byte ptr [rdi+1], dl
        mov edx, eax
        shr edx, 6
        and dl, 3Fh
        or  dl, 80h
        mov byte ptr [rdi+2], dl
        and al, 3Fh
        or  al, 80h
        mov byte ptr [rdi+3], al
        add rdi, 4
        jmp next
enc3:
        mov edx, eax
        shr edx, 12
        or  dl, 0E0h
        mov byte ptr [rdi], dl
        mov edx, eax
        shr edx, 6
        and dl, 3Fh
        or  dl, 80h
        mov byte ptr [rdi+1], dl
        and al, 3Fh
        or  al, 80h
        mov byte ptr [rdi+2], al
        add rdi, 3
        jmp next
enc2:
        mov edx, eax
        shr edx, 6
        or  dl, 0C0h
        mov byte ptr [rdi], dl
        and al, 3Fh
        or  al, 80h
        mov byte ptr [rdi+1], al
        add rdi, 2
        jmp next
store_dl:
        mov byte ptr [rdi], dl
        inc rdi
        jmp next
done:
        mov byte ptr [rdi], 0
        mov rax, rdi
        sub rax, r8
        ret
parse_string endp

; hex4: four hex digits at r12 -> eax
hex4 proc
        mov rdx, r13
        sub rdx, r12
        cmp rdx, 4
        jb  fail_json
        xor eax, eax
        mov ecx, 4
digit:
        movzx edx, byte ptr [r12]
        inc r12
        shl eax, 4
        cmp dl, '0'
        jb  fail_json
        cmp dl, '9'
        jbe dec_digit
        or  dl, 20h
        cmp dl, 'a'
        jb  fail_json
        cmp dl, 'f'
        ja  fail_json
        sub dl, 'a' - 10
        jmp add_digit
dec_digit:
        sub dl, '0'
add_digit:
        or  eax, edx
        dec ecx
        jnz digit
        ret
hex4 endp

; check_name: name at r14, length in rax
check_name proc
        test rax, rax
        jz  fail_name
        cmp byte ptr [r14], '.'
        jne scan
        cmp rax, 1
        je  fail_name
        cmp rax, 2
        jne scan
        cmp byte ptr [r14+1], '.'
        je  fail_name
scan:
        mov rcx, rax
        mov rdi, r14
@@:     mov dl, byte ptr [rdi]
        test dl, dl
        jz  fail_name
        cmp dl, '/'
        je  fail_name
        inc rdi
        dec rcx
        jnz @B
        ret
check_name endp

;------------------------------------------------------------------ file system
; stat_entry: rdi = dirfd, name at r14 -> rax = -1 (none), 0 (not a directory), 1 (directory)
stat_entry proc
        mov rsi, r14
        lea rdx, statbuf
        mov r10d, AT_SYMLINK_NOFOLLOW
        mov eax, SYS_NEWFSTATAT
        syscall
        cmp rax, -ENOENT
        je  none
        test rax, rax
        js  fail_fs
        mov eax, dword ptr [statbuf + 24]       ; st_mode
        and eax, S_IFMT
        cmp eax, S_IFDIR
        sete al
        movzx eax, al
        ret
none:
        mov rax, -1
        ret
stat_entry endp

; clear_entry: rdi = dirfd; removes a non-directory entry, fails on a directory
clear_entry proc
        push rdi
        call stat_entry
        pop rdi
        test rax, rax
        js  done
        jnz fail_inway
        mov rsi, r14
        xor edx, edx
        mov eax, SYS_UNLINKAT
        syscall
        test rax, rax
        js  fail_fs
done:
        ret
clear_entry endp

; make_file: rdi = dirfd, content at r15, rdx = length, ecx = 1 for a script
make_file proc
        push rbp
        mov rbp, rsp
        sub rsp, 32
        mov qword ptr [rbp-8], rdi
        mov qword ptr [rbp-16], rdx
        mov qword ptr [rbp-24], rcx
        call clear_entry
        mov rdi, qword ptr [rbp-8]
        mov rsi, r14
        mov edx, O_WRONLY or O_CREAT or O_EXCL or O_NOFOLLOW or O_CLOEXEC
        mov r10d, 666o
        mov eax, SYS_OPENAT
        syscall
        test rax, rax
        js  fail_fs
        mov qword ptr [rbp-32], rax             ; fd
        mov rsi, r15
        mov rdx, qword ptr [rbp-16]
wloop:
        test rdx, rdx
        jz  written
        mov rdi, qword ptr [rbp-32]
        push rsi
        push rdx
        mov eax, SYS_WRITE
        syscall
        pop rdx
        pop rsi
        cmp rax, -EINTR
        je  wloop
        test rax, rax
        js  fail_fs
        add rsi, rax
        sub rdx, rax
        jmp wloop
written:
        cmp qword ptr [rbp-24], 0
        je  closeit
        mov rsi, qword ptr umaskval
        not rsi
        and rsi, 666o
        or  rsi, 111o
        mov rdi, qword ptr [rbp-32]
        mov eax, SYS_FCHMOD
        syscall
        test rax, rax
        js  fail_fs
closeit:
        mov rdi, qword ptr [rbp-32]
        mov eax, SYS_CLOSE
        syscall
        leave
        ret
make_file endp

; make_link: rdi = dirfd, target at r15, name at r14
make_link proc
        push rdi
        call clear_entry
        pop rsi                                 ; new dirfd
        mov rdi, r15
        mov rdx, r14
        mov eax, SYS_SYMLINKAT
        syscall
        test rax, rax
        js  fail_fs
        ret
make_link endp

; prep_dir: rdi = dirfd, name at r14 -> rax = fd of the (existing or new) directory
prep_dir proc
        push rdi
        call stat_entry
        mov rdi, qword ptr [rsp]
        cmp rax, 1
        je  opendir
        test rax, rax
        js  mk
        mov rsi, r14                            ; not a directory: remove it
        xor edx, edx
        mov eax, SYS_UNLINKAT
        syscall
        test rax, rax
        js  fail_fs
        mov rdi, qword ptr [rsp]
mk:
        mov rsi, r14
        mov edx, 777o
        mov eax, SYS_MKDIRAT
        syscall
        test rax, rax
        js  fail_fs
        mov rdi, qword ptr [rsp]
opendir:
        mov rsi, r14
        mov edx, O_DIRECTORY or O_NOFOLLOW or O_CLOEXEC
        xor r10d, r10d
        mov eax, SYS_OPENAT
        syscall
        test rax, rax
        js  fail_fs
        pop rdi
        ret
prep_dir endp

fileend:
_TEXT   ends
        end
