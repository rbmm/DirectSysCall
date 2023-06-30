#include "stdafx.h"

struct SSN  
{
	ULONG Address, Name;

	static int __cdecl Compare(void const* pa, void const* pb)
	{
		ULONG a = reinterpret_cast<const SSN*>(pa)->Address;
		ULONG b = reinterpret_cast<const SSN*>(pb)->Address;

		if (a < b) return -1;
		if (a > b) return +1;
		return 0;
	}

	static int __cdecl Compare2(void const* pa, void const* pb)
	{
		ULONG a = reinterpret_cast<const SSN*>(pa)->Name;
		ULONG b = reinterpret_cast<const SSN*>(pb)->Name;

		if (a < b) return -1;
		if (a > b) return +1;
		return 0;
	}
};

ULONG GetZwCount(_In_ PVOID ImageBase, _In_ ULONG NumberOfNames, _In_ PULONG AddressOfNames)
{
	ULONG n = 0;

	do 
	{
		PCSTR name = RtlOffsetToPointer(ImageBase, *AddressOfNames++);

		n += (name[0] == 'Z' && name[1] == 'w');

	} while (--NumberOfNames);

	return n;
}

SSN* _G_pTable;
ULONG _G_N;

//#define _PREPARE_

ULONG __fastcall SyscallNum(_In_ ULONG crc) 
{
#ifdef _PREPARE_
	__pragma(message("; " __FUNCSIG__ "\r\nextern " __FUNCDNAME__ " : PROC"));
#endif

	ULONG n = 0, N = _G_N, i;
	do 
	{
		ULONG Name = _G_pTable[i = (n + N) >> 1].Name;

		if (Name == crc)
		{
			return _G_pTable[i].Address;
		}

		Name < crc ? n = i + 1 : N = i;

	} while (n < N);

	return 0;
}

BOOL CreateSSNTable(_In_ PVOID ImageBase, _In_ PIMAGE_EXPORT_DIRECTORY pied, _Out_ SSN** ppTable, _Out_ ULONG *pN)
{
	if (ULONG NumberOfNames = pied->NumberOfNames)
	{
		PUSHORT AddressOfNameOrdinals = (PUSHORT)RtlOffsetToPointer(ImageBase, pied->AddressOfNameOrdinals);
		PULONG AddressOfNames = (PULONG)RtlOffsetToPointer(ImageBase, pied->AddressOfNames);
		PULONG AddressOfFunctions = (PULONG)RtlOffsetToPointer(ImageBase, pied->AddressOfFunctions);

		if (ULONG n = GetZwCount(ImageBase, NumberOfNames, AddressOfNames))
		{
			if (SSN* q = new SSN[n])
			{
				SSN* p = q;

				ULONG rva, m = n;
				PCSTR name;

				do 
				{
					rva = *AddressOfNames++;
					name = RtlOffsetToPointer(ImageBase, rva);
					USHORT o = *AddressOfNameOrdinals++;

					if (name[0] == 'Z' && name[1] == 'w')
					{
						if (!m--)
						{
							break;
						}

						p->Name = rva + 2, p++->Address = AddressOfFunctions[o];
					}

				} while (--NumberOfNames);

				if (!NumberOfNames)
				{
					qsort(p = q, n, sizeof(SSN), SSN::Compare);

					*pN = n, *ppTable = p;

					m = 0;
					do 
					{
						p->Address = m++;
						name = RtlOffsetToPointer(ImageBase, p->Name);
						p++->Name = RtlComputeCrc32(0, const_cast<PSTR>(name), (ULONG)strlen(name));
					} while (--n);

					qsort(q, *pN, sizeof(SSN), SSN::Compare2);

					return TRUE;
				}

				delete [] q;
			}
		}
	}

	return FALSE;
}

#ifdef _PREPARE_

void PrintNames(_In_ PVOID ImageBase, _In_ PIMAGE_EXPORT_DIRECTORY pied, _In_ PCSTR txt)
{
	if (ULONG NumberOfNames = pied->NumberOfNames)
	{
		PULONG AddressOfNames = (PULONG)RtlOffsetToPointer(ImageBase, pied->AddressOfNames);
		do 
		{
			PCSTR name = RtlOffsetToPointer(ImageBase, *AddressOfNames++);

			if (*name++ == 'Z' && *name++ == 'w')
			{
				DbgPrint("%s %s\n", txt, name);
			}

		} while (--NumberOfNames);
	}
}

void PrintHashes(_In_ PVOID ImageBase, _In_ PIMAGE_EXPORT_DIRECTORY pied)
{
	if (ULONG NumberOfNames = pied->NumberOfNames)
	{
		PULONG AddressOfNames = (PULONG)RtlOffsetToPointer(ImageBase, pied->AddressOfNames);
		do 
		{
			PCSTR name = RtlOffsetToPointer(ImageBase, *AddressOfNames++);

			if (*name++ == 'Z' && *name++ == 'w')
			{
				DbgPrint("SysApi 0%08xh, Nt%s\n", RtlComputeCrc32(0, name, (ULONG)strlen(name)), name);
			}

		} while (--NumberOfNames);
	}
}

#endif

BOOL InitSsn()
{
	if (HMODULE hmod = GetModuleHandle(L"ntdll.dll"))
	{
		ULONG size;
		if (PVOID pied = RtlImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size))
		{

#ifdef _PREPARE_
			PrintNames(hmod, (PIMAGE_EXPORT_DIRECTORY)pied, "ssn_SysApi");
			PrintNames(hmod, (PIMAGE_EXPORT_DIRECTORY)pied, "imp_SysApi");
			PrintHashes(hmod, (PIMAGE_EXPORT_DIRECTORY)pied);
#endif

			return CreateSSNTable(hmod, (PIMAGE_EXPORT_DIRECTORY)pied, &_G_pTable, &_G_N);
		}
	}

	return FALSE;
}

void DestroySsn()
{
	delete [] _G_pTable;
}
