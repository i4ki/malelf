        BITS 32
        %include "util.inc.asm"

        call get_msg
db         "OWNED BY I4K",0x0a
msg:
        pop ecx
        mov edx, 13
        mov ebx, 1
        mov eax, 4
        int 0x80

        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx

        jmp exit

get_msg:        jmp msg
exit:
