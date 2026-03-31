ragma once

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <processthreadsapi.h>
#include <string.h>  



class Injector {

	static DWORD GetPid(wchar_t* procName) {
		HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Enumerating All Process Using This API call, Using TH32CS_SNAPPROCESS flag to snap all process.

		PROCESSENTRY32 a; // PROCESSENTRY32 is a macro for a functions that we define his name "a".
		a.dwSize = sizeof(a); // dwSize is one of it's arguments we need to fill, we fill the size of the function, sizeof(a).

		while (Process32First(&h, &a)) { // walking loop into the process, see winAPI for Process32First to understand the arguments
			do {
				if (_wcsicmp(procName, a.szExeFile) == 0) { // XOR operation returns 0 if equal, Wide Char String Ignore Compare.
					CloseHandle(h); // closing Handle for cleanup.
					return a.th32ProcessID; // returning process ID
				}
			} while (Process32Next(&h, &a)); // we need to walk into all the structure, we need a next to not stop at first.
		}

		CloseHandle(h); // needs a cleanup even if not successful

		return 0; // returning 0 if not successful


	}

	static uintptr_t GetBase(DWORD pid) {
		HANDLE hp = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, pid); // same thing but for modules

		MODULEENTRY32 b;
		b.dwSize = sizeof(b);

		while (Module32First(&hp, &b)) {
			do {
				if (pid == b.th32ProcessID) {
					CloseHandle(hp);
					return (uintptr_t)b.modBaseAddr;
				}
			} while (Module32Next(&hp, &b));
		}

		CloseHandle(hp);

		return 0;

	}


	static std::vector<DWORD> EnumThreads(std::vector<DWORD> t, DWORD pid) {
		HANDLE hc = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);

		THREADENTRY32 th;
		th.dwSize = sizeof(th);

		while (Thread32First(&hc, &th)) {
			do {
				if (th.th32OwnerProcessID == pid) {
					t.push_back(th.th32ThreadID);
				}
			} while (Thread32Next(&hc, &th));
		}
		
		CloseHandle(hc);
		

	}

	static PVOID ThreadInjection(DWORD ThID, DWORD entryPoint) {
		HANDLE ct = OpenThread(THREAD_ALL_ACCESS, true, ThID); 

		if (!SuspendThread(&ct) > -1) {                                                /* NEED TO ADD THIS FUCKING ERROR HANDLING */
			std::cout << "failed to Suspend Thread" << std::endl;
		}



		_CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_FULL;

		GetThreadContext(&ct, &ctx);
		ctx.Rip = NULL; // needs to be replaced to our code pointer or reference (would prefer reference -> &) incase the pointer is NULL for x reasons.
		ctx.Rcx = (DWORD64)entryPoint; // entryPoint
		ctx.Rdx = DLL_PROCESS_ATTACH; // FdwReason =  1
		ctx.R8 = NULL; // LpReserved 


		if (SetThreadContext(&ct, &ctx) == NULL) {
			std::cout << "Failed to Set Thread Context" << std::endl;
		}

		if (!ResumeThread(&ct) > -1) {
			std::cout << "Failed To Resume Thread" << std::endl;
		}



	}

	static DWORD ManualMap(std::vector<BYTE>tb, HANDLE ThreadHandle) { /* Need to finish this tommorow */

		/* Walking DosHeaders and NtHeaders of our dll Bytes */

		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)tb.data();
		IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(tb.data() + dos->e_lfanew);

		/* Allocating for it*/

		LPVOID alloc = VirtualAllocEx(ThreadHandle, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		/* Walking into all the sections */

		PIMAGE_SECTION_HEADER ntH = (PIMAGE_SECTION_HEADER)nt;


		for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
			memmove(ThreadHandle, (BYTE*)alloc + ntH[i].VirtualAddress, nt->OptionalHeader.SizeOfImage);
		}

		/* Fixing relocations */

		DWORD delta = (uintptr_t)alloc - nt->OptionalHeader.ImageBase;


		PIMAGE_DATA_DIRECTORY dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(nt->OptionalHeader.ImageBase + dir->VirtualAddress);

		while (reloc->VirtualAddress != 0) {
			DWORD size = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD relocentry = (PWORD)(reloc + 1);

			for (DWORD i = 0; i < size; i++) {
				WORD test = relocentry[i] >> 12; // Page Offset Table ( pml4 -> pdpt -> pd -> pt -> PageOffSetTable )
				WORD tt = relocentry[i] & 0x0FFF;

				if (test == IMAGE_REL_BASED_HIGHLOW || test == IMAGE_REL_BASED_DIR64) {
					uintptr_t* correctBase = (uintptr_t*)(&alloc + reloc->VirtualAddress + tt);

					*correctBase += delta;
				}


			}


		}

		reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock); // Next Block To fix


		/* Fixing Imports */

		
		IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; /* Importing Import Directory */
		PIMAGE_IMPORT_DESCRIPTOR desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)alloc + dir->VirtualAddress); /* Moving through it */


		const char* dll = (char*)(BYTE*)alloc + desc->Name;
		HMODULE handle = LoadLibraryA(dll);

		while (!handle) {
			desc++;
			if (handle) {
				break;
			}
		}

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)alloc + desc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA IAT = (PIMAGE_THUNK_DATA)((BYTE*)alloc + desc->FirstThunk);

		while(thunk->u1.AddressOfData != 0) { 
		if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) { /* if it's set, import by ordinal, else import by name.*/
			WORD ordinal = IMAGE_ORDINAL(thunk->u1.Ordinal);

			IAT->u1.Function = (ULONG_PTR)GetProcAddress(handle, (LPCSTR)ordinal);
		}
		else {
			PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)alloc + thunk->u1.AddressOfData);
			char* funcname = name->Name;

			IAT->u1.Function = (ULONG_PTR)GetProcAddress(handle, (LPCSTR)funcname);
		}
		thunk++; /*  original thunk of the import (ILT)*/
		IAT++; /* First thunk of the import*/
		}
		desc++; /* Next Import */



		BYTE EntryPoint = (BYTE)(&alloc + nt->OptionalHeader.AddressOfEntryPoint);
		
		return EntryPoint;

	}

};
