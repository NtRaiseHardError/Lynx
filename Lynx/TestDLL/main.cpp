#include <iostream>
#include <Windows.h>

BOOL APIENTRY MyMain(LPVOID lpParameter) {
	DWORD dwImageBase = reinterpret_cast<DWORD>(lpParameter);

	//WCHAR szOutput[MAX_PATH];
	//wsprintf(szOutput, L"Module base: 0x%08x", dwImageBase);
	::MessageBox(NULL, TEXT("This is the test DLL!"), TEXT("Test DLL"), MB_OK);

	return TRUE;
}