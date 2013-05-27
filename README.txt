injector v1.0

===============

A generic, simple command line Win32 DLL injector with an option to eject libraries as well.
Can act on either a window name or a specific PID.
Can elevate privileges to evade certain weak protection schemes that attempt to block this.

injector [windowname] [pid] [dllname] -fnphs
	-hH? - Display the help message and quit.
	-vV - Display version message and quit.
	-fF - Free the specified dll instead of load it.
	-nN - Don't raise the privileges of this utility to SeDebugPrivilege.
	-sS - Load specified library from system directory, not the current working directory.
	-pP - The PID is explicitly specified in place of the window name.
