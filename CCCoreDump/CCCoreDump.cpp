#include "stdafx.h"
#include "CCCoreDump.h"
#include <iostream>
#include <tchar.h>
using namespace std;
#include <windows.h>  
#include <DbgHelp.h>  
#include <stdlib.h>  
#pragma comment(lib, "dbghelp.lib")  
LPCTSTR G_dumpFileName;
inline BOOL IsDataSectionNeeded(const WCHAR* pModuleName)
{
	if (pModuleName == 0)
	{
		return FALSE;
	}

	WCHAR szFileName[_MAX_FNAME] = L"";
	_wsplitpath(pModuleName, NULL, NULL, szFileName, NULL);

	if (_wcsicmp(szFileName, L"ntdll") == 0)
		return TRUE;

	return FALSE;
}

inline BOOL CALLBACK MiniDumpCallback(PVOID                            pParam,
	const PMINIDUMP_CALLBACK_INPUT   pInput,
	PMINIDUMP_CALLBACK_OUTPUT        pOutput)
{
	if (pInput == 0 || pOutput == 0)
		return FALSE;

	switch (pInput->CallbackType)
	{
	case ModuleCallback:
		if (pOutput->ModuleWriteFlags & ModuleWriteDataSeg)
		if (!IsDataSectionNeeded(pInput->Module.FullPath))
			pOutput->ModuleWriteFlags &= (~ModuleWriteDataSeg);
	case IncludeModuleCallback:
	case IncludeThreadCallback:
	case ThreadCallback:
	case ThreadExCallback:
		return TRUE;
	default:;
	}

	return FALSE;
}

inline void CreateMiniDump(PEXCEPTION_POINTERS pep, LPCTSTR strFileName)
{
	HANDLE hFile = CreateFile(strFileName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
	{
		MINIDUMP_EXCEPTION_INFORMATION mdei;
		mdei.ThreadId = GetCurrentThreadId();
		mdei.ExceptionPointers = pep;
		mdei.ClientPointers = NULL;

		MINIDUMP_CALLBACK_INFORMATION mci;
		mci.CallbackRoutine = (MINIDUMP_CALLBACK_ROUTINE)MiniDumpCallback;
		mci.CallbackParam = 0;

		::MiniDumpWriteDump(::GetCurrentProcess(), ::GetCurrentProcessId(), hFile, MiniDumpNormal, (pep != 0) ? &mdei : 0, NULL, &mci);

		CloseHandle(hFile);
	}
}

LONG __stdcall MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo)
{

	CreateMiniDump(pExceptionInfo, G_dumpFileName);

	return EXCEPTION_EXECUTE_HANDLER;
}
// 此函数一旦成功调用，之后对 SetUnhandledExceptionFilter 的调用将无效  
void DisableSetUnhandledExceptionFilter()
{
	void* addr = (void*)GetProcAddress(LoadLibrary((LPCTSTR)"kernel32.dll"),
		"SetUnhandledExceptionFilter");

	if (addr)
	{
		int size = 0;
		unsigned char code[16];
		code[size++] = 0x33;
		code[size++] = 0xC0;
		code[size++] = 0xC2;
		code[size++] = 0x04;
		code[size++] = 0x00;
		
		DWORD dwOldFlag, dwTempFlag;
		VirtualProtect(addr, size, PAGE_READWRITE, &dwOldFlag);
		WriteProcessMemory(GetCurrentProcess(), addr, code, size, NULL);
		VirtualProtect(addr, size, dwOldFlag, &dwTempFlag);
	}
}
wchar_t DumpFileName[1024];

extern "C"
{
	void InitMinDump(char *dumpFileName)
	{

		int len = MultiByteToWideChar(CP_ACP, 0, dumpFileName, -1, NULL, 0);
		memset(DumpFileName, 0, 1024);
		MultiByteToWideChar(CP_ACP, 0, dumpFileName, -1, DumpFileName, len);

		memset(DumpFileName, 0, 1024);
		MultiByteToWideChar(CP_ACP, 0, dumpFileName, -1, DumpFileName, len);

		G_dumpFileName = (LPCTSTR)(LPTSTR)DumpFileName;

		//注册异常处理函数  
		SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);

		//使SetUnhandledExceptionFilter  
		DisableSetUnhandledExceptionFilter();
	}
}