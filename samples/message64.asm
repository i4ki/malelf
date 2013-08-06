	BITS 64        
	call get_msg
        db "HACKED BY i4k",0xa
continue:
	pop rsi

	; write(1, message, 14)
        mov     rax, 1                ; system call 1 is write
        mov     rdi, 1                ; file handle 1 is stdout
        mov     rdx, 14               ; number of bytes
        syscall                       ; invoke operating system to do the write

	jmp entry_point
get_msg:
	jmp continue

entry_point:
	
