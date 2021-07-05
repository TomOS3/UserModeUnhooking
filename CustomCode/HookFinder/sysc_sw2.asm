.code

NtRVM PROC
	mov eax, 003fh
	mov r10, rcx
	syscall
	ret
NtRVM ENDP

NtOP PROC
	mov eax, 0026h
	mov r10, rcx
	syscall
	ret
NtOP ENDP


end