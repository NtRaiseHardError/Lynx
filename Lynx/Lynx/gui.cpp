#include <string>
#include <Windows.h>
#include <CommCtrl.h>
#include <TlHelp32.h>

#include "gui.h"
#include "helper.h"
#include "injector.h"
#include "resource.h"

#pragma comment(lib, "ComCtl32.lib")

#define RED RGB(0xFF, 0, 0)
#define GREEN RGB(0, 0xFF, 0)

void OutputString(HWND hDlg, LPCWSTR fmt, ...) {
	va_list args;
	va_start(args, fmt);

	WCHAR szOutput[MAX_PATH];
	vswprintf(szOutput, fmt, args);
	::SetDlgItemText(hDlg, IDC_STATIC, szOutput);

	va_end(args);
}

void UpdateProgressBar(HWND hDlg, int nValue, bool bError) {
	if (bError)
		::SendMessage(::GetDlgItem(hDlg, IDC_PROGRESS1), PBM_SETBARCOLOR, 0, static_cast<LPARAM>(RED));
	else
		::SendMessage(::GetDlgItem(hDlg, IDC_PROGRESS1), PBM_SETBARCOLOR, 0, static_cast<LPARAM>(GREEN));

	// -1 means keep same value
	if (nValue >= 0)
		::SendMessage(::GetDlgItem(hDlg, IDC_PROGRESS1), PBM_SETPOS, static_cast<WPARAM>(nValue), 0);
}

bool SaveFile(HWND hDlg, std::wstring& szSaveFileName) {
	LPOPENFILENAME lpOfn = new OPENFILENAME;
	WCHAR szFileName[MAX_PATH] = L"";

	::ZeroMemory(lpOfn, sizeof(OPENFILENAME));

	lpOfn->lStructSize = sizeof(OPENFILENAME);
	lpOfn->hwndOwner = hDlg;
	lpOfn->lpstrFilter = L"Executable Files (*.exe)\0*.txt\0All Files (*.*)\0*.*\0";
	lpOfn->lpstrFile = szFileName;
	lpOfn->nMaxFile = MAX_PATH;
	lpOfn->Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT | OFN_CREATEPROMPT;
	lpOfn->lpstrDefExt = L"exe";

	if (!::GetSaveFileName(lpOfn))
		return false;

	szSaveFileName = std::wstring(szFileName);

	delete lpOfn;

	return true;
}

bool OpenFile(HWND hDlg, std::wstring& szOpenFileName) {
	LPOPENFILENAME lpOfn = new OPENFILENAME;
	WCHAR szFileName[MAX_PATH] = L"";

	ZeroMemory(lpOfn, sizeof(OPENFILENAME));

	lpOfn->lStructSize = sizeof(OPENFILENAME);
	lpOfn->hwndOwner = hDlg;
	lpOfn->lpstrFile = szFileName;
	lpOfn->lpstrFile[0] = '\0';
	lpOfn->nMaxFile = MAX_PATH;
	lpOfn->lpstrFilter = L"DLL Files (*.dll)\0*.txt\0All Files (*.*)\0*.*\0";
	lpOfn->nFilterIndex = 1;
	lpOfn->lpstrFileTitle = NULL;
	lpOfn->nMaxFileTitle = 0;
	lpOfn->lpstrInitialDir = NULL;
	lpOfn->Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (!::GetOpenFileName(lpOfn))
		return false;

	szOpenFileName = std::wstring(szFileName);

	delete lpOfn;

	return true;
}

bool GetProcesses(HWND hDlg) {
	// clear list entries
	::SendMessage(::GetDlgItem(hDlg, IDC_LIST1), LB_RESETCONTENT, 0, 0);

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (::Process32First(hSnapshot, &pe32)) {
		while (::Process32Next(hSnapshot, &pe32)) {
			BOOL bWow64 = FALSE;
			HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
			if (::IsWow64Process(hProcess, &bWow64) && bWow64 == TRUE)
				::SendMessage(::GetDlgItem(hDlg, IDC_LIST1), LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(pe32.szExeFile));
			::CloseHandle(hProcess);
		}
	} else
		return ::CloseHandle(hSnapshot), false;

	::CloseHandle(hSnapshot);

	return true;
}

bool UpdatePayload(HWND hDlg) {
	OutputString(hDlg, L"Feature is currently unavailable");

	return false;
}

std::wstring GetProcessName(HWND hDlg) {
	// get item index from process list
	int nIndex = ::SendMessage(::GetDlgItem(hDlg, IDC_LIST1), LB_GETCURSEL, 0, 0);
	int nTextLen = ::SendMessage(::GetDlgItem(hDlg, IDC_LIST1), LB_GETTEXTLEN, static_cast<WPARAM>(nIndex), 0);

	LPWSTR szText = new WCHAR[nTextLen];
	::SendMessage(::GetDlgItem(hDlg, IDC_LIST1), LB_GETTEXT, static_cast<WPARAM>(nIndex), reinterpret_cast<LPARAM>(szText));
	std::wstring szProcessName(szText);

	delete[] szText;

	return szProcessName;
}

bool InjectPayload(HWND hDlg, std::wstring& szProcessName) {
	Injector *i = new Injector(szProcessName);
	// check if module has DLL payload
	OutputString(hDlg, L"Checking for existing payload...\n");
	if (i->HasPayload()) {
		UpdateProgressBar(hDlg, 33, false);
		// load DLL payload
		OutputString(hDlg, L"Loading payload...\n");
		if (i->LoadFromResource()) {
			UpdateProgressBar(hDlg, 66, false);
			// inject into target process
			OutputString(hDlg, L"Injecting payload...\n");
			if (i->InjectPayload()) {
				UpdateProgressBar(hDlg, 100, false);
				// execute DLL
				OutputString(hDlg, L"Executing payload...\n");
				INT nExitCode = i->ExecuteDll(false, true);
				// OutputString(hDlg, L"Thread returned with exit code: %d\n", nExitCode);
			} else {
				OutputString(hDlg, L"Failed to execute payload: %lu\n", GetLastError());
				UpdateProgressBar(hDlg, -1, true);
			}
		} else {
			OutputString(hDlg, L"Failed to locate payload:%lu\n", GetLastError());
			UpdateProgressBar(hDlg, -1, true);
		}
	} else {
		OutputString(hDlg, L"Failed to locate payload: %lu\n", GetLastError());
		UpdateProgressBar(hDlg, -1, true);
	}
	
	return true;
}

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
		case WM_INITDIALOG:
			GetProcesses(hDlg);
			OutputString(hDlg, L"Ready.");
			return TRUE;
		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDC_REFRESH:
					GetProcesses(hDlg);
					::EnableWindow(::GetDlgItem(hDlg, IDC_INJECT), FALSE);
					return TRUE;
				case IDC_UPDATE:
					UpdatePayload(hDlg);
					return TRUE;
				case IDC_ABOUT:

					return TRUE;
				case IDC_INJECT:
					InjectPayload(hDlg, GetProcessName(hDlg));
					return TRUE;
				case IDC_LIST1:
					switch (HIWORD(wParam)) {
						case LBN_SELCHANGE:
							::EnableWindow(::GetDlgItem(hDlg, IDC_INJECT), TRUE);
							break;
						case LBN_SELCANCEL:
							::EnableWindow(::GetDlgItem(hDlg, IDC_INJECT), FALSE);
							break;
					}
					return TRUE;
			}
			break;

		case WM_CLOSE:
			::DestroyWindow(hDlg);
			return TRUE;

		case WM_DESTROY:
			::PostQuitMessage(0);
			return TRUE;
	}

	return FALSE;
}

int GuiMain(HINSTANCE hInstance) {
	HWND hDlg = ::CreateDialogParam(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), 0, DialogProc, 0);
	::ShowWindow(hDlg, SW_SHOW);

	MSG msg;
	BOOL ret;
	while ((ret = ::GetMessage(&msg, 0, 0, 0)) != 0) {
		if (ret == -1)
			return -1;

		if (!IsDialogMessage(hDlg, &msg)) {
			::TranslateMessage(&msg);
			::DispatchMessage(&msg);
		}
	}

	return 0;
}