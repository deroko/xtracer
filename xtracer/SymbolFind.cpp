#include "defs.h"

SymbolFind::SymbolFind(void)
{
	sympath = "SRV*C:\\Symbols*http://msdl.microsoft.com/download/symbols";
	hSym = (HANDLE)0xDEADC0DE;
	dllBase = 0;
	ErrorMessage = new char[1204];
	strcpy(ErrorMessage, "No error");
}

SymbolFind::~SymbolFind(void)
{
	this->UnloadSymbols();
	delete[] ErrorMessage;
}

bool SymbolFind::InitSymbols()
{
	BOOL b;
	::SymSetOptions(SYMOPT_LOAD_LINES|SYMOPT_FAVOR_COMPRESSED);
	b = ::SymInitialize(hSym, this->sympath, FALSE);
	
	if (!b){
		SetError("SymInitialize failed");
		return false;
	}

	return true;
}

void SymbolFind::UnloadSymbols()
{
	::SymUnloadModule64(hSym, dllBase);
	::SymCleanup(hSym);
}

void SymbolFind::SetError(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vsprintf_s(ErrorMessage, 1024, format, ap);
	va_end(ap);
}

char * SymbolFind::GetError()
{
	return ErrorMessage;
}

bool SymbolFind::LoadModule(LPSTR moduleName, bool b_driver){
	HMODULE imagebase;
	char *FullName, *rootName;
	DWORD64 moduleBase;
	PULONG_PTR driverBase;
	DWORD dummy, numOfDrivers;
	bool b;

	if (!b_driver){
		imagebase = ::LoadLibraryA(moduleName);
		if (!imagebase){
			SetError("Failed to load : %s", moduleName);
			return false;
		}

		FullName = new char[MAX_PATH];
		if (!::GetModuleFileNameA(imagebase, FullName, MAX_PATH)){
			::FreeLibrary(imagebase);
			delete[] FullName;
			SetError("Failed to get Full Path for module : %s", moduleName);
			return false;
		}

		moduleBase = (DWORD64)imagebase;
		dllBase = (DWORD64)imagebase;

		if (!::SymLoadModule64(this->hSym, NULL, FullName, NULL, moduleBase, 0)){
			::FreeLibrary(imagebase);
			delete[] FullName;
			SetError("Failed to load symbols for module : %s", moduleName);
			return false;
		}

		return true;
	}

	driverBase = new ULONG_PTR[1024];

	if (!::EnumDeviceDrivers((PVOID *)driverBase, sizeof(ULONG_PTR) * 1024, &dummy)){
		delete[] driverBase;	
		SetError("Failed to enumerate drivers");
		return false;
	}

	numOfDrivers = dummy / sizeof(ULONG_PTR);

	FullName = new char[MAX_PATH];
	b = false;
	for (DWORD i = 0; i < numOfDrivers; i++){
		if (::GetDeviceDriverBaseNameA((PVOID)driverBase[i], FullName, MAX_PATH)){
			if (!::stricmp(moduleName, FullName)){
				::GetDeviceDriverFileNameA((PVOID)driverBase[i], FullName, MAX_PATH);
				moduleBase = driverBase[i];
				dllBase = driverBase[i];
				rootName = new char[MAX_PATH];
				if (!::strnicmp(FullName, "\\SystemRoot\\", strlen("\\SystemRoot\\"))){
					::GetWindowsDirectoryA(rootName, MAX_PATH);
					::strcat_s(rootName, MAX_PATH, &FullName[strlen("\\SystemRoot")]);

				}else{
					::GetEnvironmentVariableA("SystemDrive", rootName, MAX_PATH);
					::strcat_s(rootName, MAX_PATH, FullName);
				}
				b = true;
				break;
			}
		}
	}

	if (!b){
		delete[] FullName;
		delete[] driverBase;
		SetError("Failed to find device driver : %s", moduleName);
		return false;
	}

	if (!::SymLoadModule64(hSym, NULL, rootName, NULL, moduleBase, 0)){
		delete[] FullName;
		delete[] driverBase;
		delete[] rootName;
		SetError("Failed to load symbols for device driver : %s", moduleName);
		return false;
	}

	delete[] FullName;
	delete[] driverBase;
	delete[] rootName;

	return true;
}

BOOL CALLBACK SymbolFind::SymEnumSymbolsProc(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext){
	SYMCALLBACK user_callback = (SYMCALLBACK)UserContext;

	return user_callback(pSymInfo->Address, (LPSTR)&pSymInfo->Name);
}

bool SymbolFind::EnumSymbols(SYMCALLBACK user_callback){
	if (!::SymEnumSymbols(hSym, dllBase, NULL, this->SymEnumSymbolsProc, (PVOID)user_callback)){
		SetError("Failed to enumerate symbols");
		return false;
	}
	return true;
}


