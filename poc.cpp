#include "stdafx.h"
#include "ssn.h"

void CALLBACK ep(void*)
{
	if (InitSsn())
	{
		IO_STATUS_BLOCK iosb;
		HANDLE hFile;
		UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\systemroot");
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };

		ULONG n = 2;
		do 
		{
			if (0 <= NtOpenFile(&hFile, SYNCHRONIZE, &oa, &iosb, 0, FILE_SYNCHRONOUS_IO_NONALERT))
			{
				FILE_INTERNAL_INFORMATION fii;
				NtQueryInformationFile(hFile, &iosb, &fii, sizeof(fii), FileInternalInformation);
				NtClose(hFile);
			}
		} while (--n);

		DestroySsn();
	}

	ExitProcess(0);
}