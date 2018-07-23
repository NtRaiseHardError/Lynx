#include <iostream>
#include <string>
#include <locale>
#include <codecvt>
#include <Windows.h>

#include "console.h"
#include "helper.h"
#include "injector.h"

#define CONSOLE_WINDOW_TITLE L"Lynx DLL Injector v1.0"

struct _params {
	std::wstring lpProcessName;
	std::wstring lpUpdatePayload;
	DWORD dwOptions;
};

VOID CreateConsole() {
	::AllocConsole();
	::AttachConsole(::GetCurrentProcessId());
	::SetConsoleTitle(CONSOLE_WINDOW_TITLE);
	freopen("CON", "w", stdout);
	freopen("CON", "w", stderr);
}

VOID DestroyConsole() {
	::FreeConsole();
}

VOID PauseConsole() {
	WCHAR szTmp[2];
	DWORD dwRead = 0;

	//::WriteConsole
	std::wcerr << L"Press Enter to continue...";
	::ReadConsole(::GetStdHandle(STD_INPUT_HANDLE), szTmp, 1, &dwRead, NULL);
}

/*
* Console syntax: argv[0] -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> -o <OUTPUT FILE> [--obfuscate]
*/
VOID PrintUsage(LPCWSTR self) {
	std::wcerr << self << L" -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]\n";
	PauseConsole();
	ExitProcess(1);
}

VOID ExecutePayload(Injector *i) {
	// check if module has DLL payload
	Debug(L"Checking for existing payload...\n");
	if (i->HasPayload()) {
		// load DLL payload
		Debug(L"Loading payload...\n");
		if (i->LoadFromResource()) {
			// inject into target process
			Debug(L"Injecting payload...\n");
			if (i->InjectPayload()) {
				// execute DLL
				Debug(L"Executing payload...\n");
				INT nExitCode = i->ExecuteDll(true, true);
				Debug(L"Thread returned with exit code: %d\n", nExitCode);
			} else
				Debug(L"Failed to execute payload\n");
		} else
			Debug(L"Failed to locate payload\n");
	} else
		Debug(L"Failed to locate payload: %lu\n", GetLastError());

	PauseConsole();
}

VOID UpdatePayload(Injector *i, std::wstring lpFileName) {
	// create new file

	// read file

	// load from disk

	// update file resources

	// clean up
}

int ConsoleMain(int argc, wchar_t *argv[]) {
	// get a console window
	CreateConsole();

	// check correct number of parameters (3)
	if (argc < 3)
		PrintUsage(argv[0]);

	struct _params *p = new struct _params;

	// parse command line
	for (int i = 0; i < argc; i++) {
		// target process name
		if (!wcsicmp(argv[i], L"-p"))
			p->lpProcessName = std::wstring(argv[i + 1]);

		// update DLL payload resource
		else if (!wcsicmp(argv[i], L"-u"))
			p->lpUpdatePayload = std::wstring(argv[i + 1]);

		// obfuscate updated DLL payload
		else if (!wcsicmp(argv[i], L"--obfuscate"))
			p->dwOptions |= OPTIONS_OBFUSCATE;
	}

	// reject if both are either empty or not empty
	if ((p->lpProcessName.empty() && p->lpUpdatePayload.empty()) ||
		!p->lpProcessName.empty() && !p->lpUpdatePayload.empty())
		PrintUsage(argv[0]);


	// if target process
	if (!p->lpProcessName.empty()) {
		Debug(L"You've selected to inject into process: %s\n", p->lpProcessName.c_str());
		// create new injector object
		Injector *i = new Injector(p->lpProcessName);
		ExecutePayload(i);
		delete i;

	// else if update payload
	} else if (!p->lpUpdatePayload.empty()) {
		Debug(L"You've selected to update your payload with %s\n", p->lpUpdatePayload.c_str());
		Injector *i = new Injector(p->lpUpdatePayload, p->dwOptions);
		UpdatePayload(i, p->lpUpdatePayload);
		delete i;
	}

	// clean up
	delete p;

	// free console window
	DestroyConsole();

	return 0;
}