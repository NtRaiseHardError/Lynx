#include <Windows.h>

#include "console.h"
#include "gui.h"

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShow) {
	int argc = 0;
	LPWSTR *argv = ::CommandLineToArgvW(::GetCommandLine(), &argc);

	if (argc < 2)
		return GuiMain(hInstance);
	else
		return ConsoleMain(argc, argv);
}