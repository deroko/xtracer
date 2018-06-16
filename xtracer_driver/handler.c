#include        "defs.h"

extern ULONG start_range;
extern ULONG end_range;
extern PKEVENT event;
extern ULONG ActiveCr3;
extern BOOLEAN b_pae;
extern KEVENT  ma_thread_event;
extern KEVENT  int0e_event;


extern MMACCESSFAULT   MmAccessFault;

extern TRACER_DATA td;
BOOLEAN b_disabled = FALSE;

BOOLEAN HandleAccessViolation(PREGSX86 regs){
        NTSTATUS status;
        PPTE     pte;
        PPTE_NOPAE pte_nopae;
        ULONG   c_cr2;
        ULONG   dummy;
        PLINEAR_ADDRESS_PTE pLinearPte;
        PLINEAR_ADDRESS_PTE_NOPAE pLinearPte_nopae;
        
        // not interested in not present pages
        // basically, we may handle them here by
        // calling MmAccessFault to bring back these
        // pages, but let windows to perform such
        // action...
        if (!TestBit(regs->regErrorCode, 0))               
                return FALSE;
        
        // although cr2 is passed in regs struct, it's safe to read it again due to cli
        c_cr2 = __readcr2();
                
        // check range
        if (c_cr2 < start_range)
                return FALSE;
        if (c_cr2 >= end_range)
                return FALSE;
        
        //check if we have r/w or execute on this range     
        if (c_cr2 != regs->regEip){
                if (b_pae){
                        pte = PTE_OFFSET;
                        pLinearPte = (PLINEAR_ADDRESS_PTE)&c_cr2;
                        pte[pLinearPte->Table].UserSupervisor = 1;
                        // as this is present memory, it could be
                        // already loaded in DTLB from ring0 so
                        // clear TLB for this address!!   
                        __invlpg(c_cr2);        
                        // load DTLB
                        __asm mov eax, c_cr2
                        __asm mov eax, [eax]    
                
                        // set page again supervisor as CPU will use DTLB
                        // to lookup page for data access
                        pte[pLinearPte->Table].UserSupervisor = 0;
                        
                        if (!pte[pLinearPte->Table].ReadWrite && TestBit(regs->regErrorCode, 1)){
                                pte[pLinearPte->Table].UserSupervisor = 1;
                                status = MmAccessFault((regs->regErrorCode >> 1) & 1, (PVOID)c_cr2, UserMode, 0);
                                // do cli immidiately to stop everything on this cpu...
                                // note that, at this point it's completly different 
                                // physical page due to MiCopyOnWrite...
                                __asm   cli
                                // MmAccessFault will return 0 on success, and error codes describing
                                // if it's ACCESS_VIOLATION or PAGE_GUARD... basically both of these
                                // 2 remain on disk for a good. 
                                if (!NT_SUCCESS(status)){
                                        //FIX ME :
                                        // - PAGE_GUARD, PAGE_NO_ACCESS - don't set anything
                                        //   check first if page is present, although I doubt it is!!!
                                        if (pte[pLinearPte->Table].Present)
                                                pte[pLinearPte->Table].UserSupervisor = 0;
                                        return FALSE;
                                }
                                
                                // everythig worked ok, so refresh TLB again...
                                __invlpg(c_cr2);
                                __asm mov eax, c_cr2
                                __asm mov eax, [eax]
                                pte[pLinearPte->Table].UserSupervisor = 0;
                                return TRUE;
                        }
                        
                        return TRUE;
                }else{
                        pte_nopae = PTE_OFFSET_NOPAE;
                        pLinearPte_nopae = (PLINEAR_ADDRESS_PTE_NOPAE)&c_cr2;
                        pte_nopae[pLinearPte_nopae->Table].UserSupervisor = 1;
                        __invlpg(c_cr2);
                        __asm mov eax, c_cr2
                        __asm mov eax, [eax]
                        pte_nopae[pLinearPte_nopae->Table].UserSupervisor = 0;
                        if (!pte_nopae[pLinearPte_nopae->Table].ReadWrite && TestBit(regs->regErrorCode, 1)){
                                pte_nopae[pLinearPte_nopae->Table].UserSupervisor = 1;
                                status = MmAccessFault((regs->regErrorCode >> 1) & 1, (PVOID)c_cr2, UserMode, 0);
                                // do cli as above!!!
                                __asm cli
                                if (!NT_SUCCESS(status)){
                                        // FIX ME : as noted above in PAE handling...
                                        if (pte_nopae[pLinearPte->Table].Present)
                                        pte_nopae[pLinearPte_nopae->Table].UserSupervisor = 0;
                                        return FALSE;
                                }
                                
                                __invlpg(c_cr2);
                                __asm mov eax, c_cr2
                                __asm mov eax, [eax]
                                pte_nopae[pLinearPte_nopae->Table].UserSupervisor = 0;
                                return TRUE;
                        }
                        return TRUE;
                }
        }
                
        // check if this is fault due to instruction fetch                      
        // DbgPrint("ITLB break at %.08X\n", regs->regEip);
        
        InterlockedExchange(&ActiveCr3, 0xFFFFFFFF);     
        td.eip   = regs->regEip;
        td.state = s_wait;
        KeSetEvent(event, IO_NO_INCREMENT, FALSE);  
        while (td.state == s_wait)
                ZwYieldExecution();
        
        // signal thread, and tell it to kill U/S flag :)
        KeSetEvent(&ma_thread_event, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(&int0e_event, Executive, KernelMode, FALSE, NULL);
        
        regs->regEip = td.eip;
        
        return TRUE;                
}

        
        
        
        
