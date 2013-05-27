/*-
 * Copyright (c) 2007 Ryan Kwolek
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright notice, this list of
 *     conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * injector.c - 
 *    A generic, simple command line DLL injector with an option to eject libraries as well
 */


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#define ARG_WINDOWNAME 1
#define ARG_DLLNAME	   2
#define ARG_OPTIONS	   3

#define VERSION_MSG "Injector 1.0\n" \
	"Copyright (c) 2007 Ryan Kwolek\n" \
	"This utility has been released under the Simplified BSD copyright license.\n\n"

#define HELP_MSG "injector [windowname] [pid] [dllname] -fnphs?\n" \
				 "\thH? - Display this help message and quit.\n" \
				 "\tvV - Display version message and quit.\n" \
				 "\tfF - Free the specified dll instead of load it.\n" \
				 "\tnN - Don't raise the privileges of this utility to SeDebugPrivilege.\n" \
				 "\tsS - Load specified library from system directory, not the current working directory." \
				 "\tpP - The PID is explicitly specified in place of the window name.\n\n"

int freedll;
int noelevateprivs;
int sysdir;


////////////////////////////////////////////////////////////////////////////////////////////////


void DispErr(const char *fnname) {
	printf("%s failed, error %d\nquitting now.\n", GetLastError());
	exit(0);
}


int main(int argc, char *argv[]) {
	unsigned long pid, len;
	void *remotelib;
	char dllname[MAX_PATH];
	HANDLE hToken, hProcess, hThread;
	HMODULE kernel32lib;
	LPTHREAD_START_ROUTINE procaddr;
	HWND hwnd;
	LUID luid;
	TOKEN_PRIVILEGES tp, oldtp;

	pid = 0;

	if (argc < 2) {
		puts("not enough args!");
		return 0;
	} else if (argc == 2) {
		if (*argv[1] == '-') {
			switch (argv[1][1]) {
				case 'h':
				case 'H':
				case '?':
					puts(HELP_MSG);
					return 0;
				case 'v':
				case 'V':
					puts(VERSION_MSG);
					return 0;
			}
		}
	} else if (argc >= 4) {
		if (*argv[ARG_OPTIONS] == '-') {
			char *tmp = argv[ARG_OPTIONS] + 1;
			while (*tmp) {
				switch (*tmp) {
					case 'f': /*free dll*/
					case 'F':
						freedll = 1;
						break;
					case 'n': /*don't elevate privileges*/
					case 'N':
						noelevateprivs = 1;
						break;
					case 's': /*load from system directory*/
					case 'S':
						sysdir = 1;
						break;
					case 'p': /*specify pid to inject*/
					case 'P':
						pid = atoi(argv[ARG_WINDOWNAME]);
					default:
						printf("WARNING: unrecognized option %c, "
							"ignoring.\n", *tmp);
				}
				tmp++;
			}
		}
	}

	if (!pid) {
		hwnd = FindWindow(NULL, argv[ARG_WINDOWNAME]);
		if (!hwnd)
			DispErr("FindWindow");

		printf("found window: 0x%x\n", hwnd);
		GetWindowThreadProcessId(hwnd, &pid);
	}

	printf("process pid: %d\n", pid);

	if (!noelevateprivs) {
		if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
			DispErr("OpenProcessToken");
		printf("process token opened, handle 0x%x\n", hToken);

		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
			DispErr("LookupPrivilegeValue");
		printf("debug luid: %08x:%08x\n", luid.HighPart, luid.LowPart);

		len = sizeof(TOKEN_PRIVILEGES);

		tp.PrivilegeCount         = 1;
		tp.Privileges->Luid       = luid;
		tp.Privileges->Attributes = 0;
		if (!AdjustTokenPrivileges(hToken, 0, &tp,
			sizeof(TOKEN_PRIVILEGES), &oldtp, &len))
			DispErr("AdjustTokenPrivileges");

		oldtp.PrivilegeCount = 1;
		oldtp.Privileges->Luid = luid;
		oldtp.Privileges->Attributes |= SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &oldtp,
			sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			DispErr("re AdjustTokenPrivileges");

		puts("elevated process privileges sucessfully!");
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
								  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
								  PROCESS_VM_READ, 0, pid);
	if (!hProcess)
		DispErr("OpenProcess");


	if (sysdir) {
		strncpy(dllname, argv[ARG_DLLNAME], sizeof(dllname));
		len = strlen(dllname) + 1;
	} else {
		len = GetCurrentDirectory(sizeof(dllname), dllname);
		if (!len)
			DispErr("GetCurrentDirectory");
		*(short *)(dllname + len) = '\\';
		len++;
		strncpy(dllname + len, argv[ARG_DLLNAME], sizeof(dllname) - len);
		len = strlen(dllname) + 1;
	}

	remotelib = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT, PAGE_READWRITE);
	if (!remotelib)
		DispErr("VirtualAllocEx");

	WriteProcessMemory(hProcess, remotelib, dllname, len, NULL);	

	kernel32lib = GetModuleHandle("kernel32");

	procaddr = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32lib,
		freedll ? "FreeLibraryA" : "LoadLibraryA")

	hThread = CreateRemoteThread(hProcess, NULL, 0,
		procaddr, remotelib, 0, NULL);
	if (!hThread)
		DispErr("CreateRemoteThread");
	CloseHandle(hThread);

	printf("successfully %sjected %s into %d, thread handle 0x%08x.\n",
		freedll ? "de" : "in", dllname, pid, hThread);
	return 0;
}

