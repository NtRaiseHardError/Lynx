#include <Windows.h>

#include "console.h"
#include "gui.h"

__declspec(dllexport) int func(int a, int b) {
	return a - b;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShow) {
	int argc = 0;
	LPWSTR *argv = ::CommandLineToArgvW(::GetCommandLine(), &argc);

	if (argc < 2)
		return GuiMain(hInstance);
	else
		return ConsoleMain(argc, argv);
}