.code

; Reference: https://j00ru.vexillium.org/syscalls/nt/64/

; ---------------------------------------------------------------------
; Windows 7 SP1 / Server 2008 R2 specific syscalls
; ---------------------------------------------------------------------

NtCreateFile7SP1 proc
		mov r10, rcx
		mov eax, 52h
		syscall
		ret
NtCreateFile7SP1 endp

NtCreateSection7SP1 proc
		mov r10, rcx
		mov eax, 47h
		syscall
		ret
NtCreateSection7SP1 endp

NtMapViewOfSection7SP1 proc
		mov r10, rcx
		mov eax, 25h
		syscall
		ret
NtMapViewOfSection7SP1 endp

NtProtectVirtualMemory7SP1 proc
		mov r10, rcx
		mov eax, 4Dh
		syscall
		ret
NtProtectVirtualMemory7SP1 endp

NtUnmapViewOfSection7SP1 proc
		mov r10, rcx
		mov eax, 27h
		syscall
		ret
NtUnmapViewOfSection7SP1 endp

NtClose7SP1 proc
		mov r10, rcx
		mov eax, 0Ch
		syscall
		ret
NtClose7SP1 endp

;----------------------------------------------------------------------
; Windows 8 / Server 2012 specific syscalls
; ---------------------------------------------------------------------

NtCreateFile80 proc
		mov r10, rcx
		mov eax, 53h
		syscall
		ret
NtCreateFile80 endp

NtCreateSection80 proc
		mov r10, rcx
		mov eax, 48h
		syscall
		ret
NtCreateSection80 endp

NtMapViewOfSection80 proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
NtMapViewOfSection80 endp

NtProtectVirtualMemory80 proc
		mov r10, rcx
		mov eax, 4Eh
		syscall
		ret
NtProtectVirtualMemory80 endp

NtUnmapViewOfSection80 proc
		mov r10, rcx
		mov eax, 28h
		syscall
		ret
NtUnmapViewOfSection80 endp

NtClose80 proc
		mov r10, rcx
		mov eax, 0Dh
		syscall
		ret
NtClose80 endp

;----------------------------------------------------------------------
; Windows 8.1 / Server 2012 R2 specific syscalls
; ---------------------------------------------------------------------

NtCreateFile81 proc
		mov r10, rcx
		mov eax, 54h
		syscall
		ret
NtCreateFile81 endp

NtCreateSection81 proc
		mov r10, rcx
		mov eax, 49h
		syscall
		ret
NtCreateSection81 endp

NtMapViewOfSection81 proc
		mov r10, rcx
		mov eax, 27h
		syscall
		ret
NtMapViewOfSection81 endp

NtProtectVirtualMemory81 proc
		mov r10, rcx
		mov eax, 4Fh
		syscall
		ret
NtProtectVirtualMemory81 endp

NtUnmapViewOfSection81 proc
		mov r10, rcx
		mov eax, 29h
		syscall
		ret
NtUnmapViewOfSection81 endp

NtClose81 proc
		mov r10, rcx
		mov eax, 0Eh
		syscall
		ret
NtClose81 endp

;----------------------------------------------------------------------
; Windows 10 / Server 2016 specific syscalls
; ---------------------------------------------------------------------

NtCreateFile10 proc
		mov r10, rcx
		mov eax, 55h
		syscall
		ret
NtCreateFile10 endp

NtCreateSection10 proc
		mov r10, rcx
		mov eax, 4Ah
		syscall
		ret
NtCreateSection10 endp

NtMapViewOfSection10 proc
		mov r10, rcx
		mov eax, 28h
		syscall
		ret
NtMapViewOfSection10 endp

NtProtectVirtualMemory10 proc
		mov r10, rcx
		mov eax, 50h
		syscall
		ret
NtProtectVirtualMemory10 endp

NtUnmapViewOfSection10 proc
		mov r10, rcx
		mov eax, 2Ah
		syscall
		ret
NtUnmapViewOfSection10 endp

NtClose10 proc
		mov r10, rcx
		mov eax, 0Fh
		syscall
		ret
NtClose10 endp

ZOP10 proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
ZOP10 endp

; ---------------------------------------------------------------------
  end
; ---------------------------------------------------------------------