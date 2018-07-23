#include <iostream>
#include <Windows.h>

#include "helper.h"

//VOID Debug(LPCTSTR fmt, ...) {
//	va_list args;
//	va_start(args, fmt);
//
//#ifdef _UNICODE
//	vwprintf(fmt, args);
//#else
//	vprintf(fmt, args);
//#endif // _UNICODE
//
//	va_end(args);
//}

VOID DebugW(LPCWSTR fmt, ...) {
	va_list args;
	va_start(args, fmt);

	DWORD dwWrite = 0;
	WCHAR szOutput[MAX_PATH];
	vswprintf(szOutput, fmt, args);
	::WriteConsole(::GetStdHandle(STD_OUTPUT_HANDLE), szOutput, wcslen(szOutput), &dwWrite, NULL);

	va_end(args);
}

VOID DebugA(LPCSTR fmt, ...) {
	va_list args;
	va_start(args, fmt);

	vprintf(fmt, args);

	va_end(args);
}