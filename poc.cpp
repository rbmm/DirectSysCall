#include "stdafx.h"
#include "ssn.h"

void MapNt32()
{
	HANDLE hSection;
	UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\KnownDlls32\\ntdll.dll");
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_EXECUTE, &oa);

	if (0 <= status)
	{
		PIMAGE_DOS_HEADER hmod = 0;
		SIZE_T s = 0;
		status = NtMapViewOfSection(hSection, NtCurrentProcess(), (void**)&hmod, 0, 0, 0, &s, ViewUnmap, 0, PAGE_EXECUTE);
		NtClose(hSection);

		if (0 <= status)
		{
			NtUnmapViewOfSection(NtCurrentProcess(), hmod);
		}
	}
}

void Ft()
{
	IO_STATUS_BLOCK iosb;
	HANDLE hFile;
	UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\systemroot");
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	if (0 <= NtOpenFile(&hFile, SYNCHRONIZE, &oa, &iosb, 0, FILE_SYNCHRONOUS_IO_NONALERT))
	{
		FILE_INTERNAL_INFORMATION fii;
		NtQueryInformationFile(hFile, &iosb, &fii, sizeof(fii), FileInternalInformation);
		NtClose(hFile);
	}
}

void CALLBACK ep(void*)
{
#ifdef _PREPARE_
	static const PCSTR _S_names[] = {
		"OpenSection", 
		"MapViewOfSection",
		"OpenFile", 
		"QueryInformationFile",
		"Close",
		"UnmapViewOfSection",
		0
	};

	Prepare(_S_names);
#endif

	if (InitSysCall())
	{
		ULONG n = 2;

		do 
		{
			Ft();
			MapNt32();
		} while (--n);

		DestroySysCall();
	}

	ExitProcess(0);
}