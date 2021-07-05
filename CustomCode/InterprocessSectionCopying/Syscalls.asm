.code

; Reference: https://j00ru.vexillium.org/syscalls/nt/64/

; Windows 7 SP1 / Server 2008 R2 specific syscalls

ZwOpenProcess7SP1 proc
		mov r10, rcx
		mov eax, 23h
		syscall
		ret
ZwOpenProcess7SP1 endp

ZwClose7SP1 proc
		mov r10, rcx
		mov eax, 0Ch
		syscall
		ret
ZwClose7SP1 endp

ZwWriteVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 37h
		syscall
		ret
ZwWriteVirtualMemory7SP1 endp

ZwProtectVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 4Dh
		syscall
		ret
ZwProtectVirtualMemory7SP1 endp

ZwQuerySystemInformation7SP1 proc
		mov r10, rcx
		mov eax, 33h
		syscall
		ret
ZwQuerySystemInformation7SP1 endp

NtAllocateVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 15h
		syscall
		ret
NtAllocateVirtualMemory7SP1 endp

NtFreeVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 1Bh
		syscall
		ret
NtFreeVirtualMemory7SP1 endp

NtCreateFile7SP1 proc
		mov r10, rcx
		mov eax, 52h
		syscall
		ret
NtCreateFile7SP1 endp

; Windows 8 / Server 2012 specific syscalls

ZwOpenProcess80 proc
		mov r10, rcx
		mov eax, 24h
		syscall
		ret
ZwOpenProcess80 endp

ZwClose80 proc
		mov r10, rcx
		mov eax, 0Dh
		syscall
		ret
ZwClose80 endp

ZwWriteVirtualMemory80 proc
		mov r10, rcx
		mov eax, 38h
		syscall
		ret
ZwWriteVirtualMemory80 endp

ZwProtectVirtualMemory80 proc
		mov r10, rcx
		mov eax, 4Eh
		syscall
		ret
ZwProtectVirtualMemory80 endp

ZwQuerySystemInformation80 proc
		mov r10, rcx
		mov eax, 34h
		syscall
		ret
ZwQuerySystemInformation80 endp

NtAllocateVirtualMemory80 proc
		mov r10, rcx
		mov eax, 16h
		syscall
		ret
NtAllocateVirtualMemory80 endp

NtFreeVirtualMemory80 proc
		mov r10, rcx
		mov eax, 1Ch
		syscall
		ret
NtFreeVirtualMemory80 endp

NtCreateFile80 proc
		mov r10, rcx
		mov eax, 53h
		syscall
		ret
NtCreateFile80 endp

; Windows 8.1 / Server 2012 R2 specific syscalls

ZwOpenProcess81 proc
		mov r10, rcx
		mov eax, 25h
		syscall
		ret
ZwOpenProcess81 endp

ZwClose81 proc
		mov r10, rcx
		mov eax, 0Eh
		syscall
		ret
ZwClose81 endp

ZwWriteVirtualMemory81 proc
		mov r10, rcx
		mov eax, 39h
		syscall
		ret
ZwWriteVirtualMemory81 endp

ZwProtectVirtualMemory81 proc
		mov r10, rcx
		mov eax, 4Fh
		syscall
		ret
ZwProtectVirtualMemory81 endp

ZwQuerySystemInformation81 proc
		mov r10, rcx
		mov eax, 35h
		syscall
		ret
ZwQuerySystemInformation81 endp

NtAllocateVirtualMemory81 proc
		mov r10, rcx
		mov eax, 17h
		syscall
		ret
NtAllocateVirtualMemory81 endp

NtFreeVirtualMemory81 proc
		mov r10, rcx
		mov eax, 1Dh
		syscall
		ret
NtFreeVirtualMemory81 endp

NtCreateFile81 proc
		mov r10, rcx
		mov eax, 54h
		syscall
		ret
NtCreateFile81 endp

; Windows 10 / Server 2016 specific syscalls
 
ZwOpenProcess10 proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
ZwOpenProcess10 endp

ZwClose10 proc
		mov r10, rcx
		mov eax, 0Fh
		syscall
		ret
ZwClose10 endp

ZwWriteVirtualMemory10 proc
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
ZwWriteVirtualMemory10 endp

ZwProtectVirtualMemory10 proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
ZwProtectVirtualMemory10 endp

ZwQuerySystemInformation10 proc
		mov r10, rcx
		mov eax, 36h
		syscall
		ret
ZwQuerySystemInformation10 endp

NtAllocateVirtualMemory10 proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
NtAllocateVirtualMemory10 endp

NtFreeVirtualMemory10 proc
		mov r10, rcx
		mov eax, 1Eh
		syscall
		ret
NtFreeVirtualMemory10 endp

NtCreateFile10 proc
		mov r10, rcx
		mov eax, 55h
		syscall
		ret
NtCreateFile10 endp

NtReadVirtualMemory PROC
	mov rax, gs:[60h]                         ; Load PEB into RAX.
NtReadVirtualMemory_Check_X_X_XXXX:               ; Check major version.
	cmp dword ptr [rax+118h], 10
	je  NtReadVirtualMemory_Check_10_0_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_10_0_XXXX:              ; Check build number for Windows 10.
	cmp word ptr [rax+120h], 10240
	je  NtReadVirtualMemory_SystemCall_10_0_10240
	cmp word ptr [rax+120h], 10586
	je  NtReadVirtualMemory_SystemCall_10_0_10586
	cmp word ptr [rax+120h], 14393
	je  NtReadVirtualMemory_SystemCall_10_0_14393
	cmp word ptr [rax+120h], 15063
	je  NtReadVirtualMemory_SystemCall_10_0_15063
	cmp word ptr [rax+120h], 16299
	je  NtReadVirtualMemory_SystemCall_10_0_16299
	cmp word ptr [rax+120h], 17134
	je  NtReadVirtualMemory_SystemCall_10_0_17134
	cmp word ptr [rax+120h], 17763
	je  NtReadVirtualMemory_SystemCall_10_0_17763
	cmp word ptr [rax+120h], 18362
	je  NtReadVirtualMemory_SystemCall_10_0_18362
	cmp word ptr [rax+120h], 18363
	je  NtReadVirtualMemory_SystemCall_10_0_18363
	cmp word ptr [rax+120h], 19041
	je  NtReadVirtualMemory_SystemCall_10_0_19041
	cmp word ptr [rax+120h], 19042
	je  NtReadVirtualMemory_SystemCall_10_0_19042
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_SystemCall_10_0_10240:        ; Windows 10.0.10240 (1507)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10586:        ; Windows 10.0.10586 (1511)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_14393:        ; Windows 10.0.14393 (1607)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_15063:        ; Windows 10.0.15063 (1703)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_16299:        ; Windows 10.0.16299 (1709)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17134:        ; Windows 10.0.17134 (1803)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17763:        ; Windows 10.0.17763 (1809)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18362:        ; Windows 10.0.18362 (1903)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18363:        ; Windows 10.0.18363 (1909)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19041:        ; Windows 10.0.19041 (2004)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19042:        ; Windows 10.0.19042 (20H2)
	mov eax, 003fh
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_Unknown:           ; Unknown/unsupported version.
	ret
NtReadVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret
NtReadVirtualMemory ENDP

end
