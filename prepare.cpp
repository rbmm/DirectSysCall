#include "stdafx.h"
#include "ssn.h"

#ifdef _PREPARE_

ULONG HashString(PCSTR lpsz, ULONG hash = 0);

void PrepareCode(_In_ const PCSTR names[])
{
	while (PCSTR name = *names++)
	{
		DbgPrint("SysApi 0%08xh, Nt%s\n", HashString(name), name);
	}
}

void PrepareData(_In_ const PCSTR names[])
{
	while (PCSTR name = *names++)
	{
		DbgPrint("imp_SysApi Nt%s\n", name);
	}
}

void Prepare(_In_ const PCSTR names[])
{
	PrepareCode(names);

	DbgPrint("\n.data\n\n");

	PrepareData(names + 2);
}

#endif