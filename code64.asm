
; unsigned long __cdecl SyscallNum(unsigned long)
extern ?SyscallNum@@YAKK@Z : PROC

SysApi MACRO hash, name
@CatStr(?,name) proc
	mov r10,rcx
	mov eax,@CatStr(@,name)
	test eax,eax
	jns @@0
	mov ecx,hash
	call gscn
	mov @CatStr(@,name),eax
@@0:
	syscall
	ret
@CatStr(?,name) endp
ENDM

imp_SysApi MACRO name
@CatStr(__imp_,name) DQ @CatStr(?,name)
public @CatStr(__imp_,name)
ENDM

ssn_SysApi MACRO name
@CatStr(@,name) DD -1
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

SysApi 00a25cef4h, NtOpenFile 
SysApi 0d2c0aec0h, NtClose
SysApi 06a41d829h, NtQueryInformationFile

.const

imp_SysApi NtOpenFile
imp_SysApi NtClose
imp_SysApi NtQueryInformationFile

.data

ssn_SysApi NtOpenFile
ssn_SysApi NtClose
ssn_SysApi NtQueryInformationFile

end