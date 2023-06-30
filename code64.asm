
; unsigned long __cdecl SyscallNum(unsigned long)
extern ?SyscallNum@@YAKK@Z : PROC

; void *__cdecl SyscallAddr(unsigned long)
extern ?SyscallAddr@@YAPEAXK@Z : PROC

_SysApi MACRO hash, name
@CatStr(@@,name) proc
	lea rax,@CatStr(?,name)
	mov @CatStr(__imp_,name),rax
	mov r10,rcx
	mov ecx,hash
	call gscn
@@0:
	syscall
	ret
@CatStr(@@,name) endp
ENDM

imp_SysApi2 MACRO name, addr
@CatStr(__imp_,name) DQ addr
public @CatStr(__imp_,name)
ENDM

imp_SysApi MACRO name
imp_SysApi2 name, @CatStr(?,name)
ENDM

SysApi MACRO hash, name
@CatStr(?,name) proc
	mov eax,hash
	call gsca
	mov @CatStr(__imp_,name),rax
@@0:
	jmp rax
@CatStr(?,name) endp
ENDM

.code

gscn proc
	push rdx
	push r8
	push r9
	push r10
	sub rsp,20h
	call ?SyscallNum@@YAKK@Z
	add rsp,20h
	pop r10
	pop r9
	pop r8
	pop rdx
	ret
gscn endp

gsca proc
	push rcx
	push rdx
	push r8
	push r9
	sub rsp,20h
	mov ecx,eax
	call ?SyscallAddr@@YAPEAXK@Z
	add rsp,20h
	pop r9
	pop r8
	pop rdx
	pop rcx
	ret
gsca endp

.data

imp_SysApi2 NtOpenSection, @@NtOpenSection
imp_SysApi2 NtMapViewOfSection, @@NtMapViewOfSection

.code

_SysApi 0f0e4fe7dh, NtOpenSection
_SysApi 098fd3231h, NtMapViewOfSection

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; ++ used api

SysApi 0f0e4fe7dh, NtOpenSection
SysApi 098fd3231h, NtMapViewOfSection
SysApi 09c6e4b92h, NtOpenFile
SysApi 03f1a3f60h, NtQueryInformationFile
SysApi 004d4d176h, NtClose
SysApi 051e82f8ah, NtUnmapViewOfSection

.data

imp_SysApi NtOpenFile
imp_SysApi NtQueryInformationFile
imp_SysApi NtClose
imp_SysApi NtUnmapViewOfSection

;; -- used api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

end