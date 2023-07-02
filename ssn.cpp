#include "stdafx.h"
#include "ssn.h"

struct SSN  
{
	ULONG Address, hash;

	static int __cdecl Compare(void const* pa, void const* pb)
	{
		ULONG a = reinterpret_cast<const SSN*>(pa)->Address;
		ULONG b = reinterpret_cast<const SSN*>(pb)->Address;

		if (a < b) return -1;
		if (a > b) return +1;
		return 0;
	}
};

static union {
	PVOID _G_hmod;
	ULONG _G_N;
};

static union {
	PIMAGE_EXPORT_DIRECTORY _G_pied;
	SSN* _G_pTable;
};

BOOL MapNt()
{
	HANDLE hSection;
	UNICODE_STRING ObjectName = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_EXECUTE, &oa);

	if (0 <= status)
	{
		PIMAGE_DOS_HEADER hmod = 0;
		SIZE_T s = 0;
		status = NtMapViewOfSection(hSection, NtCurrentProcess(), (void**)&hmod, 0, 0, 0, &s, ViewUnmap, 0, PAGE_EXECUTE);
		CloseHandle(hSection);

		if (0 <= status)
		{
			PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(hmod, hmod->e_lfanew);

			if (offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT + 1]) <=
				pinth->FileHeader.SizeOfOptionalHeader)
			{
				if (ULONG VirtualAddress = pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
				{
					delete [] _G_pTable;

					_G_hmod = hmod;
					_G_pied = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(hmod, VirtualAddress);
					return TRUE;
				}
			}

			UnmapViewOfFile(hmod);
		}
	}

	return FALSE;
}

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

ULONG HashString(PCSTR lpsz, ULONG hash = 0)
{
	while (char c = *lpsz++) hash = hash * 33 ^ c;
	return hash;
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
			if (SSN* p = new SSN[n])
			{
				*pN = n, *ppTable = p;

				do 
				{
					ULONG rva = *AddressOfNames++;
					PCSTR name = RtlOffsetToPointer(ImageBase, rva);
					USHORT o = *AddressOfNameOrdinals++;

					if (*name++ == 'Z' && *name++ == 'w')
					{
						if (!n--)
						{
							break;
						}

						p->hash = HashString(name), p++->Address = AddressOfFunctions[o];
					}

				} while (--NumberOfNames);

				if (!NumberOfNames)
				{
					qsort(*ppTable, *pN, sizeof(SSN), SSN::Compare);

					return TRUE;
				}

				delete [] *ppTable;
			}
		}
	}

	return FALSE;
}

BOOL InitSysCall()
{
	PIMAGE_DOS_HEADER hmod;

	if (GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
		(PCWSTR)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr, (HMODULE*)&hmod))
	{
		PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(hmod, hmod->e_lfanew);

		if (offsetof(IMAGE_NT_HEADERS, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT + 1]) <=
			pinth->FileHeader.SizeOfOptionalHeader)
		{
			if (ULONG VirtualAddress = pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				if (CreateSSNTable(hmod, (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(hmod, VirtualAddress), &_G_pTable, &_G_N))
				{
					if (MapNt())
					{
						return TRUE;
					}

					delete [] _G_pTable;
				}
			}
		}
	}

	return FALSE;
}

void DestroySysCall()
{
	UnmapViewOfFile(_G_hmod), _G_hmod = 0;
}

PVOID __fastcall SyscallAddr(_In_ ULONG crc) 
{
#ifdef _PREPARE_
	__pragma(message("; " __FUNCSIG__ "\r\nextern " __FUNCDNAME__ " : PROC"));
#endif

	if (ULONG NumberOfNames = _G_pied->NumberOfNames)
	{
		PUSHORT AddressOfNameOrdinals = (PUSHORT)RtlOffsetToPointer(_G_hmod, _G_pied->AddressOfNameOrdinals);
		PULONG AddressOfNames = (PULONG)RtlOffsetToPointer(_G_hmod, _G_pied->AddressOfNames);
		PULONG AddressOfFunctions = (PULONG)RtlOffsetToPointer(_G_hmod, _G_pied->AddressOfFunctions);

		do 
		{
			PCSTR name = RtlOffsetToPointer(_G_hmod, *AddressOfNames++);
			USHORT o = *AddressOfNameOrdinals++;

			if ('Z' == *name++ && 'w' == *name++)
			{
				if (HashString(name) == crc)
				{
					return RtlOffsetToPointer(_G_hmod, AddressOfFunctions[o]);
				}
			}
		} while (--NumberOfNames);
	}

	__debugbreak();

	return 0;
}

ULONG __fastcall SyscallNum(_In_ ULONG crc) 
{
#ifdef _PREPARE_
	__pragma(message("; " __FUNCSIG__ "\r\nextern " __FUNCDNAME__ " : PROC"));
#endif

	ULONG i = 0, N = _G_N;
	SSN* pTable = _G_pTable;
	do 
	{
		if (pTable++->hash == crc)
		{
			return i;
		}

	} while (i++, --N);

	__debugbreak();
	return 0;
}