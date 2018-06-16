#include        <ntifs.h>
__declspec(dllimport) NTSTATUS KeSetAffinityThread(IN PETHREAD, IN KAFFINITY);
__declspec(dllimport) NTSTATUS ZwYieldExecution(VOID);

typedef struct{
        unsigned __int64        Present:1;
        unsigned __int64        ReadWrite:1;
        unsigned __int64        UserSupervisor:1;
        unsigned __int64        WriteTrough:1;
        unsigned __int64        CacheDisabled:1;
        unsigned __int64        Accessed:1;
        unsigned __int64        Dirty:1;
        unsigned __int64        Reserved0:1;
        unsigned __int64        GlobalPage:1;        
        unsigned __int64        Available:3;
        unsigned __int64        PageBaseAddress:24;
        unsigned __int64        Reserved:27;
        unsigned __int64        NxBit:1;
}PTE, *PPTE;


typedef struct{
        unsigned __int64        Present:1;
        unsigned __int64        ReadWrite:1;
        unsigned __int64        UserSupervisor:1;
        unsigned __int64        WriteTrough:1;
        unsigned __int64        CacheDisabled:1;
        unsigned __int64        Accessed:1;
        unsigned __int64        Reserved0:1;
        unsigned __int64        PageSize:1;
        unsigned __int64        GlobalPage:1;
        unsigned __int64        Avaialble:3;
        unsigned __int64        PageTableBaseAddress:24;
        unsigned __int64        Reserved:27;
        unsigned __int64        NxBit:1;
}PDE, *PPDE;

typedef struct{
        unsigned        Present:1;
        unsigned        ReadWrite:1;
        unsigned        UserSupervisor:1;
        unsigned        WriteThrough:1;
        unsigned        CacheDisabled:1;
        unsigned        Accessed:1;
        unsigned        Reserved0:1;
        unsigned        PageSize:1;
        unsigned        GlobalPage:1;
        unsigned        Available:3;
        unsigned        PageTableBaseAddress:20;
}PDE_NOPAE, *PPDE_NOPAE;

typedef struct{
        unsigned        Present:1;
        unsigned        ReadWrite:1;
        unsigned        UserSupervisor:1;
        unsigned        WriteThroug:1;
        unsigned        CacheDisabled:1;
        unsigned        Accessed:1;
        unsigned        Dirty:1;
        unsigned        PageTableAttributeIndex:1;
        unsigned        GlobalPage:1;
        unsigned        Available:3;
        unsigned        PageBaseAddress:20;
}PTE_NOPAE, *PPTE_NOPAE;

typedef struct{
        unsigned Limit:16;
        unsigned IdtBaseLo:16;
        unsigned IdtBaseHi:16;
}IDT_BASE, *PIDT_BASE;

typedef struct{
        unsigned OffsetLow:16;
        unsigned SegmentSelector:16;
        unsigned Reserved:5;
        unsigned Reverved1:3;
        unsigned Type:3;
        unsigned Size:1;
        unsigned Reserved2:1;
        unsigned Dpl:2;
        unsigned Present:1;
        unsigned OffsetHigh:16;
}IDT_ENTRY, *PIDT_ENTRY;


//due to logic used in windows we need different set 
//for PAE LINEAR_ADDRESS as DirectoryPointer and Directory
//are used as a part of PDE located at 0xC0600000, so this
//basic layout is changed for windows mapping...
//typedef struct{
//        unsigned        Offset:12;
//        unsigned        Table:9;
//        unsigned        Directory:9;
//        unsigned        DirectoryPointer:2;
//}LINEAR_ADDRESS, *PLINEAR_ADDRESS;

typedef struct{
        unsigned        Offset:12;
        unsigned        Table:9;
        unsigned        Directory:11;
}LINEAR_ADDRESS, *PLINEAR_ADDRESS;

typedef struct{
        unsigned        Offset:12;
        unsigned        Table:20;
}LINEAR_ADDRESS_PTE, *PLINEAR_ADDRESS_PTE;

// LINEAR_ADDRESS and LINEAR_ADDRESS_PTE for NON_PAE system
typedef struct{
        unsigned        Offset:12;
        unsigned        Table:10;
        unsigned        Directory:10;
}LINEAR_ADDRESS_NOPAE, *PLINEAR_ADDRESS_NOPAE;

typedef struct{
        unsigned        Offset:12;
        unsigned        Table:20;
}LINEAR_ADDRESS_PTE_NOPAE, *PLINEAR_ADDRESS_PTE_NOPAE;

#define PTE_OFFSET (PPTE)0xC0000000
#define PDE_OFFSET (PPDE)0xC0600000
#define PTE_OFFSET_NOPAE  (PPTE_NOPAE)0xC0000000
#define PDE_OFFSET_NOPAE  (PPDE_NOPAE)0xC0300000

#define PAGE_SIZE   0x1000

#define SET_RANGE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define STOP_TRACER  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define REF_EVENT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define GET_STATE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_STATE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SET_MMACCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x860, METHOD_BUFFERED, FILE_ANY_ACCESS)

        


typedef struct{
        ULONG   regCr2;
        ULONG   regEs;
        ULONG   regDs;
        ULONG   regFs;
        ULONG   regEdi;
        ULONG   regEsi;
        ULONG   regEbp;
        ULONG   regEsp;
        ULONG   regEbx;
        ULONG   regEdx;
        ULONG   regEcx;
        ULONG   regEax;
        ULONG   regErrorCode;
        ULONG   regEip;
        ULONG   regCs;
        ULONG   regEflags;
        ULONG   regEspR3;
        ULONG   regSs;
}REGSX8686, *PREGSX86;  

                                
void       new_int0e(void);
BOOLEAN    HandleAccessViolation(PREGSX86 regs);
BOOLEAN    TestBit(ULONG value, ULONG bit); 


#define s_wait    0x1
#define s_ready   0x2

        
typedef struct{
        ULONG   eip;
        ULONG   state;
}TRACER_DATA, *PTRACER_DATA;

typedef struct{
        ULONG   HandleCount;
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;  

typedef NTSTATUS  (__stdcall *MMACCESSFAULT)(
                                ULONG   ErrorMask,
                                PVOID   VirtualAddress,
                                ULONG   ProcessorMode,
                                PVOID   KTrapInformation);              
