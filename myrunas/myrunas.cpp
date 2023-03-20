// myrunas.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include "detours.h"
#include <algorithm>
#include <iostream>
#include <string>
#include <cstring>
#include <algorithm>


using namespace std;

#pragma comment(lib, "detours.lib")


int _tmain(int argc, _TCHAR* argv[])
{
	
	if (argc==1)
	{
		char szInfo[1024] = {0};
		wsprintf(szInfo, "%s", "#define mian main ", "MyRunas");
		MessageBox(GetForegroundWindow(), szInfo, "MyRunas", MB_ICONINFORMATION);
		return -1;
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	si.cb = sizeof(si);
	memset(&si, 0, sizeof(si) );	
	memset( &pi,0, sizeof(pi) );



	char szMyRunasCMDLine[1024] = {0};
	char szRunasCMDLine[1024] = {0};

	strcpy(szMyRunasCMDLine, GetCommandLine());

	strcpy(szRunasCMDLine, "runas ");

	strcat(szRunasCMDLine, strstr(szMyRunasCMDLine+strlen(__argv[0]), __argv[1]));

	char szDLL[MAX_PATH] = {0};
	GetModuleFileName(NULL, szDLL, 1024);
	strcpy(strrchr(szDLL, '\\')+1, "runasdll.dll");///runasdll.dll必须要导出函数，否则会报错
	// Start the child process. 
	if( !DetourCreateProcessWithDll( NULL,   // No module name (use command line)
		szRunasCMDLine,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi, 
		szDLL,
		NULL)
		) 
	{
		printf( "CreateProcess failed (%d)\n", GetLastError() );
		return -1;
	}

	// Wait until child process exits.
	WaitForSingleObject( pi.hProcess, INFINITE );

	// Close process and thread handles. 
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );


	
	return 0;
}

