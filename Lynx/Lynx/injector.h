#pragma once
#ifndef __INJECTOR_H__
#define __INJECTOR_H__

#include <string>
#include <vector>

// options
#define OPTIONS_OBFUSCATE	0x01

struct _payload {
	HRSRC hResPayload;
	HANDLE hProcess;
	LPVOID lpAddress;
	DWORD dwEntryPoint;
};

class Injector {
	private:
		bool bUpdate = false;
		std::wstring szProcessName;
		std::wstring szFileName;
		DWORD dwOptions = 0;
		std::vector<BYTE> vPayloadData;
		struct _payload *payload = nullptr;
		
		bool GetProcess();
		bool MemoryMapPayload(LPVOID lpPayload);
		bool BaseRelocate(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh, DWORD dwDelta);
		bool RebuildImportTable(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pinh);
		//bool ParseExportTable(HANDLE hProcess);

	public:
		Injector(std::wstring szProcessName);
		Injector(std::wstring szFileName, DWORD dwOptions);
		~Injector();

		// execute payload
		bool HasPayload();
		bool LoadFromResource();
		bool InjectPayload();
		INT ExecuteDll(bool bWait, bool bDetach);

		// update payload
		bool LoadFromDisk();
		bool UpdatePayload();
};

#endif // !__INJECTOR_H__
