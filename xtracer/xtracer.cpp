#include "defs.h"

ULONG SymAddress;
char  *symToFind;

BOOL CALLBACK SymCallBack(DWORD64 Address, LPSTR SymbolName){
	if (!strcmpi(SymbolName, symToFind)){
		SymAddress = (ULONG)Address;
		return FALSE;
	}
	SymAddress = 0;
	return TRUE;
}


int main(int argc, char* argv[])
{
        HANDLE hdevice;
        TRACER tracer;
        DWORD dummy;
        STARTUPINFOA sinfo;
        PROCESS_INFORMATION pinfo;
        HANDLE handles[2];
        DWORD wid;
        TRACER_DATA td;
        SYSTEMTIME systime;
        PPEHEADER32 pe32;
        PSECTION_HEADER section;
        HANDLE fhandle, shandle;
        ULONG_PTR mhandle;
        DWORD c_start, c_size;
        ULONG_PTR imagebase;
        LPSTR progy_name;
        SymbolFind sym;
        
        HRSRC   hRsrc;
        PVOID   resBase;
        DWORD   resSize;
        
        SC_HANDLE hscm;
        SC_HANDLE hservice;
        char           szDriverPath[MAX_PATH];
        
        
        printf("xtracer Copyright (C) 2008 deroko of ARTeam\n\n");
        
        if (argc != 2){
                printf("\nusage : xtracer <progy_to_trace>\n");
                return 1;
        }
        
        hdevice = CreateFileA("\\\\.\\tracer", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0,0);
        if (hdevice == INVALID_HANDLE_VALUE){
        
                //dump and load driver...
                hRsrc   = FindResource(GetModuleHandle(0), (LPSTR)IDR_XTRACER_DRV, "BIN");
                resBase = LockResource(LoadResource(GetModuleHandle(0), hRsrc));
                resSize = SizeofResource(GetModuleHandle(0), hRsrc);
        
                fhandle = CreateFile("xtracer.sys", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0,0);
                if (fhandle == INVALID_HANDLE_VALUE){
                        printf("[X] Failed to dump driver\n");
                        return 1;
                }
        
                if (!WriteFile(fhandle, resBase, resSize, &dummy, 0)){
                        printf("[X] Failed to dump driver\n");
                        CloseHandle(fhandle);
                        DeleteFile("xtracer.sys");
                        return 1;
                }
        
                CloseHandle(fhandle);
        
                hscm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
                if (!hscm){
                        printf("[X] Failed to creat service\n");
                        DeleteFile("xtracer.sys");
                        return 1;
                }
             
                GetFullPathName("xtracer.sys", MAX_PATH, szDriverPath, NULL);
                hservice = CreateService(hscm,
                                         "xtracer",
                                         "xtracer",
                                         SERVICE_ALL_ACCESS,
                                         SERVICE_KERNEL_DRIVER,
                                         SERVICE_DEMAND_START,
                                         SERVICE_ERROR_IGNORE,
                                         szDriverPath,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL);
                


                if (!hservice){
                        if (GetLastError() == ERROR_SERVICE_EXISTS){
                                hservice = OpenService(hscm, "xtracer", SERVICE_ALL_ACCESS);
                                if (!StartService(hservice, 0, NULL)){
                                        DeleteService(hservice);
                                        CloseServiceHandle(hservice);
                                        CloseServiceHandle(hscm);
                                        DeleteFile("xtracer.sys");
                                }else
                                        goto __AllOk;

                        }
                        printf("[X] Failed to create service\n");
                        CloseServiceHandle(hscm);
                        return 1;
                }

                
        
                if (!StartService(hservice, 0, NULL)){
                        printf("[X] Faield to start service\n");
                        DeleteService(hservice);
                        CloseServiceHandle(hservice);
                        CloseServiceHandle(hscm);
                        return 1;
                }
__AllOk:
                DeleteService(hservice);
                CloseServiceHandle(hservice);
                CloseServiceHandle(hscm);
                DeleteFile("xtracer.sys");
        
        }else
                CloseHandle(hdevice);
        
        progy_name = argv[1];
        
        sym.InitSymbols();
        if (sym.LoadModule("ntoskrnl.exe", true)) goto gogo;
        if (sym.LoadModule("ntkrnlpa.exe", true)) goto gogo;
        if (!sym.LoadModule("ntkrnlmp.exe", true)){
                printf("[X] Failed to locate ntos base... aborting\n");
                return 1;
        
        }
gogo:
        symToFind = "_MmAccessFault@16";
        sym.EnumSymbols(SymCallBack);
        if (!SymAddress){
                printf("[X] Failed to locate _MmAccessFault@16... aborting...\n");
                return 1;
        }
        
        fhandle = CreateFileA(progy_name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0,0);
        if (fhandle == INVALID_HANDLE_VALUE){
        	printf("[X] failed to open : %s\n", argv[1]);
        	return 1;
        }
        
        shandle = CreateFileMappingA(fhandle, 0, PAGE_READONLY, 0,0,0);
        mhandle = (ULONG_PTR)MapViewOfFile(shandle, FILE_MAP_READ, 0,0,0);
        if (!mhandle){
        	printf("[X] failed to open file : %s\n", argv[1]);
        	return 1;
        }
        if (PIMAGE_DOS_HEADER(mhandle)->e_magic != IMAGE_DOS_SIGNATURE){
        	printf("[X] File is not valid PE file\n");
        	return 1;
        }
        pe32 = (PPEHEADER32)(mhandle + PIMAGE_DOS_HEADER(mhandle)->e_lfanew);
        if (pe32->pe_signature != IMAGE_NT_SIGNATURE){
        	printf("[X] File is not valie PE file\n");
        	return 1;
        }
        
        imagebase = pe32->pe_imagebase;
        section = (PSECTION_HEADER)((ULONG_PTR)pe32 + 4 + sizeof(IMAGE_FILE_HEADER) + pe32->pe_sizeofoptionalheader);
        c_start = section[0].sh_virtualaddress;
        c_size  = section[0].sh_virtualsize;
        
        UnmapViewOfFile((PVOID)mhandle);
        CloseHandle(shandle);
        CloseHandle(fhandle);
        
        
        memset(&sinfo, 0, sizeof(STARTUPINFOA));
        memset(&pinfo, 0, sizeof(PROCESS_INFORMATION));
        
        HANDLE hevent = CreateEventA(NULL, false, false, NULL);
        
        hdevice = CreateFileA("\\\\.\\tracer", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0,0);
        if (hdevice == INVALID_HANDLE_VALUE){
                printf("[X] Failed to open \\\\.\\tracer device\n");
                return 1;
        }
        
        DeviceIoControl(hdevice, SET_MMACCESS, &SymAddress, 4, 0,0, &dummy, 0);
        DeviceIoControl(hdevice, REF_EVENT, &hevent, sizeof(HANDLE), NULL, 0, &dummy, NULL);
        
        GetLocalTime(&systime);
        printf("[*] Starting victim process %d:%d:%d:%d\n", systime.wHour, systime.wMinute, systime.wSecond, systime.wMilliseconds);
        if (!CreateProcessA(progy_name, 0,0,0,0, CREATE_SUSPENDED, 0,0, &sinfo, &pinfo)){
                printf("[X] Failed to start victim process...\n");
                return 1;
        }
        
        memset(&tracer, 0, sizeof(TRACER));
        tracer.pid = pinfo.dwProcessId;
        tracer.address = imagebase + c_start;
        tracer.size = c_size;
        
        printf("[*] Setting memory range\n");
        DeviceIoControl(hdevice, SET_RANGE, &tracer, sizeof(TRACER), NULL, 0, &dummy, NULL);
        SetPriorityClass(pinfo.hProcess, IDLE_PRIORITY_CLASS);
        printf("[*] Resuming victim process\n");
        ResumeThread(pinfo.hThread);
        
        handles[0] = hevent;
        handles[1] = pinfo.hProcess;
        
        wid = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        
        if (wid == 1){	//process satisfied wait...
                DeviceIoControl(hdevice, STOP_TRACER, NULL, 0, NULL, 0, &dummy, NULL);
                printf("[X] Process exited before hiting traced range\n");
                return 1;
        }
        
        DeviceIoControl(hdevice, GET_STATE, NULL, 0, &td, sizeof(TRACER_DATA), &dummy, NULL);
        
        GetLocalTime(&systime);
        printf("[*] Code section break at : 0x%.08X - %d:%d:%d:%d\n", td.eip, systime.wHour, systime.wMinute, systime.wSecond, systime.wMilliseconds);
        
        DeviceIoControl(hdevice, STOP_TRACER, NULL, 0, NULL, 0, &dummy, NULL);
        
        CloseHandle(hdevice);
        CloseHandle(hevent);
        
        return 0;
}



