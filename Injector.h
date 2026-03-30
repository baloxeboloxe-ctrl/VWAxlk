#pragma once

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <processthreadsapi.h>



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

	static PVOID ThreadInjection(DWORD ThID) {
		HANDLE ct = OpenThread(THREAD_ALL_ACCESS, true, ThID); 

		if (!SuspendThread(&ct) > -1) {                                                /* NEED TO ADD THIS FUCKING ERROR HANDLING */
			std::cout << "failed to Suspend Thread" << std::endl;
		}
		_CONTEXT ctx;
		ctx.Rip = NULL; // needs to be replaced to our code pointer or reference (would prefer reference -> &) incase the pointer is NULL for x reasons.


		if (SetThreadContext(&ct, &ctx) == NULL) {
			std::cout << "Failed to Set Thread Context" << std::endl;
		}

		if (!ResumeThread(&ct) > -1) {
			std::cout << "Failed To Resume Thread" << std::endl;
		}



	}

	static PVOID ManualMap(std::vector<DWORD>tb) { /* Need to finish this tommorow */

	}



};

