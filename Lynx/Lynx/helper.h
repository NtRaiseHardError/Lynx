#pragma once
#ifndef __HELPER_H__
#define __HELPER_H__

#ifdef _UNICODE
#define Debug	DebugW
#else
#define	Debug	DebugA
#endif // _UNICODE


//VOID Debug(LPCTSTR fmt, ...);
VOID DebugW(LPCWSTR fmt, ...);
VOID DebugA(LPCSTR fmt, ...);

#endif // !__HELPER_H__
