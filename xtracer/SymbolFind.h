#pragma once

#pragma warning(disable: 4996)

#pragma comment (lib, "psapi")
#pragma comment (lib, "dbghelp")

#define _CRT_SECURE_NO_DEPRECATE
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <Dbghelp.h>
#define SYMOPT_FAVOR_COMPRESSED         0x00800000

typedef BOOL (CALLBACK *SYMCALLBACK)(
	 DWORD64 Address,
	 LPSTR   SymbolName);


typedef struct{
	ULONG	LowPart;
	ULONG	HighPart;
}ULONG64_STRUCT, *PULONG64_STRUCT;


class SymbolFind
{
public:
	SymbolFind(void);
	~SymbolFind(void);
	bool InitSymbols();
	bool LoadModule(LPSTR moduleName, bool b_driver);
	bool EnumSymbols(SYMCALLBACK);
	void UnloadSymbols();
	char *GetError();
private:
	void SetError(const char *format, ...);
	static BOOL CALLBACK SymEnumSymbolsProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
	char *sympath;
	HANDLE hSym;
	DWORD64 dllBase;
	char *ErrorMessage;
};
