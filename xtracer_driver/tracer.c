#include        "defs.h"

WCHAR *szDevice  = L"\\Device\\tracer";
WCHAR *szSymlink = L"\\DosDevices\\tracer";
ULONG   ActiveCr3 = 0xFFFFFFFF;
HANDLE  traced_pid;
ULONG   start_range;
ULONG   end_range;
ULONG   old_int0e;
ULONG   old_int0es[32];
PVOID   KiTrap0E;

BOOLEAN       b_pae;
BOOLEAN       b_event;
BOOLEAN       b_mmaccessfault;
TRACER_DATA   td;
PKEVENT       event;
KSPIN_LOCK    spin_lock;
KEVENT        ma_thread_event;
KEVENT        int0e_event;
MMACCESSFAULT MmAccessFault;


ULONG   sn_NtProtectVirtualMemory;


BOOLEAN    TestBit(ULONG value, ULONG bit){
        if (value & (1 << bit))
                return TRUE;
        return FALSE;
}


ULONG   HookInterupt(ULONG NewIntAddress, ULONG IdtVector, PULONG OldIntTable, PULONG OldInterupt){
        ULONG OldIntHandler;
        IDT_BASE idt_base;
        PIDT_ENTRY idt_entry;
        
        __asm   sidt  idt_base      
        idt_entry = (PIDT_ENTRY)((idt_base.IdtBaseHi << 16) + idt_base.IdtBaseLo);

        __asm   pushfd
        __asm   cli

        OldIntHandler = (idt_entry[ IdtVector ].OffsetHigh <<16) + idt_entry[ IdtVector ].OffsetLow;
        idt_entry[ IdtVector ].OffsetHigh = (USHORT)(NewIntAddress >> 16);
        idt_entry[ IdtVector ].OffsetLow  = (USHORT)(NewIntAddress & 0xFFFF);
        
        if (OldIntTable != NULL)
                *OldIntTable = OldIntHandler;
        if (OldInterupt != NULL)
                if (*OldInterupt == 0)
                        *OldInterupt = OldIntHandler;
        
        __asm   popfd                           //if interupts were disabled prior to hook then don't enable them...
        return 0;
}

VOID    unloadme(IN PDRIVER_OBJECT pDriverObject){
        UNICODE_STRING us_symlink;
        PETHREAD cur_thread;
        UCHAR i;
        PULONG pTableBase;
        
        RtlInitUnicodeString(&us_symlink, szSymlink);
        IoDeleteSymbolicLink(&us_symlink);
        IoDeleteDevice(pDriverObject->DeviceObject);
        
       
        
        cur_thread = PsGetCurrentThread();
        for (i = 0; i < KeNumberProcessors; i++){
                KeSetAffinityThread(cur_thread, 1 << i);
                HookInterupt(old_int0es[i], 0x0E, NULL, NULL);
        }
        return;
}

NTSTATUS ServiceHandle(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp){
        NTSTATUS status = STATUS_NOT_IMPLEMENTED;
        ULONG  information = 0;
        PIO_STACK_LOCATION cur_sl;
        PULONG  pid;
        PEPROCESS eprocess;
        ULONG current, counter, wb;
        PPTE pte;
        PPDE pde;
        PPTE_NOPAE pte_nopae;
        PPDE_NOPAE pde_nopae;
        
        PLINEAR_ADDRESS pLinear;
        PLINEAR_ADDRESS_PTE pLinearPte;
        PLINEAR_ADDRESS_NOPAE pLinear_nopae;
        PLINEAR_ADDRESS_PTE_NOPAE pLinearPte_nopae;
        
        PULONG KiBase;
        ULONG dest, mm, kitrap;        
        HANDLE hevent;
        ULONG  dummy;
        
        
        cur_sl = IoGetCurrentIrpStackLocation( pIrp );
        
        switch (cur_sl->Parameters.DeviceIoControl.IoControlCode){
                case SET_MMACCESS:
                        if (cur_sl->Parameters.DeviceIoControl.InputBufferLength < 4){
                                status = STATUS_BUFFER_TOO_SMALL;
                                break;
                        }
                        if (b_mmaccessfault){
                                status = STATUS_SUCCESS;
                                break;
                        }
                        (ULONG)MmAccessFault = *(PULONG)pIrp->AssociatedIrp.SystemBuffer;
                        b_mmaccessfault = TRUE;
                        status = STATUS_SUCCESS;
                        break;
                                               
                case SET_RANGE:
                        if (!b_mmaccessfault)
                                break;
                        if (!event)
                                break;
                        if (cur_sl->Parameters.DeviceIoControl.InputBufferLength < 0xC){
                                status = STATUS_BUFFER_TOO_SMALL;
                                break;
                        }
                        
                        pid = (PULONG)pIrp->AssociatedIrp.SystemBuffer;
                        
                        status = PsLookupProcessByProcessId((HANDLE)pid[0], &eprocess);
                        if (status)
                                break;        
                                
                        KeAttachProcess(eprocess);               
                        __try{
                                ProbeForRead((PVOID)pid[1], pid[2], 1);
                                current = pid[1];     
                                current &= 0xFFFFF000;      
                                counter = pid[2];
                                if (counter % PAGE_SIZE)
                                        counter = counter - (counter % PAGE_SIZE) + PAGE_SIZE;
                                
                                
                                pte = PTE_OFFSET;
                                pde = PDE_OFFSET;        
                                pte_nopae = PTE_OFFSET_NOPAE;
                                pde_nopae = PDE_OFFSET_NOPAE;
                                
                                start_range = current;
                                end_range   = current + counter;
                                
                                while (counter){
                                        
                                        __asm mov eax, current
                                        __asm mov eax, [eax]    //pagein page...
                                        pLinear = (PLINEAR_ADDRESS)&current;
                                        pLinearPte = (PLINEAR_ADDRESS_PTE)&current;
                                        pLinear_nopae = (PLINEAR_ADDRESS_NOPAE)&current;
                                        pLinearPte_nopae = (PLINEAR_ADDRESS_PTE_NOPAE)&current;
                                        
                                        if (b_pae)
                                                pte[pLinearPte->Table].UserSupervisor = 0;
                                        else
                                                pte_nopae[pLinearPte_nopae->Table].UserSupervisor = 0;
                                                
                                        __invlpg((PVOID)current);        
                                       
                                        counter -= PAGE_SIZE;
                                        current += PAGE_SIZE;
                                        
                                }
                                        
                        }__except(EXCEPTION_EXECUTE_HANDLER){
                                status = GetExceptionCode();
                                KeDetachProcess();
                                ObDereferenceObject(eprocess);
                                break;
                        }
                  
                        dummy = __readcr3();
                        
                        InterlockedExchange(&ActiveCr3, dummy);
                        traced_pid = (HANDLE)pid[0];  
                        KeDetachProcess();              
                        ObDereferenceObject(eprocess);
                               
                        status = STATUS_SUCCESS;
                        break; 
                case STOP_TRACER:
                        if (event){
                                ObDereferenceObject(event);
                                InterlockedExchange((ULONG *)&event, 0);
                        }
                        dummy = 0xFFFFFFFF;
                        InterlockedExchange(&ActiveCr3, dummy);
                        InterlockedExchange(&td.state, s_ready);
                        status = STATUS_SUCCESS;
                        break; 
                case REF_EVENT:
                        if (event){
                                ObDereferenceObject(event);
                                InterlockedExchange((ULONG *)&event, 0);
                        }
                        
                        if (cur_sl->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE)){
                                status = STATUS_BUFFER_TOO_SMALL;
                                break;
                        }
                        
                        hevent = *(HANDLE *)pIrp->AssociatedIrp.SystemBuffer;
                        
                        status = ObReferenceObjectByHandle(hevent, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, &event, NULL);
                        if (!NT_SUCCESS(status)) break;
                        
                        status = STATUS_SUCCESS;
                        break; 
                case GET_STATE:
                        if (cur_sl->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TRACER_DATA)){
                                status = STATUS_BUFFER_TOO_SMALL;
                                break;
                        }
                        
                        memcpy(pIrp->AssociatedIrp.SystemBuffer, &td, sizeof(TRACER_DATA));
                        information = sizeof(TRACER_DATA);
                        status = STATUS_SUCCESS;
                        break;
                        
                case SET_STATE:
                        if (cur_sl->Parameters.DeviceIoControl.InputBufferLength < sizeof(TRACER_DATA)){
                                status = STATUS_BUFFER_TOO_SMALL;
                                break;
                        }
                        
                        memcpy(&td, pIrp->AssociatedIrp.SystemBuffer, sizeof(TRACER_DATA));
                        status = STATUS_SUCCESS;
                        break;                               
                default:
                        break;
        }
        
        pIrp->IoStatus.Status = status;
        pIrp->IoStatus.Information = information;
        IofCompleteRequest(pIrp, IO_NO_INCREMENT);
        return status;        
}

NTSTATUS CreateClose(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp){
        NTSTATUS status = STATUS_SUCCESS;
        ULONG    information = 0;  
        PIO_STACK_LOCATION cur_sl;
        PDEVICE_EXTENSION pExtension;
        
        cur_sl = IoGetCurrentIrpStackLocation (pIrp);      
        
        pExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
        
        switch (cur_sl->MajorFunction){
                case IRP_MJ_CREATE:
                        if (InterlockedIncrement(&pExtension->HandleCount) > 1 ){
                                status = STATUS_SHARING_VIOLATION;
                                InterlockedDecrement(&pExtension->HandleCount);
                                break;
                        }
                        status = STATUS_SUCCESS;
                        break;             
                case IRP_MJ_CLOSE:
                        if (event){
                                ObDereferenceObject(event);
                                InterlockedExchange((ULONG *)&event, 0);
                        }
                        InterlockedExchange(&ActiveCr3, 0xFFFFFFFF);
                        InterlockedDecrement(&pExtension->HandleCount);
                        InterlockedExchange(&td.state, s_ready);
                        status = STATUS_SUCCESS;
                        break;
                default:
                        status = STATUS_NOT_IMPLEMENTED;
                        break;        
        }
        
        pIrp->IoStatus.Status = status;
        pIrp->IoStatus.Information = information;
        IofCompleteRequest(pIrp, IO_NO_INCREMENT);
        return status;        
}

// thread responsible for killing u/s flags
// this assures that system is running at PASSIVE_LEVEL
// and also synchronization is performed between this
// thread and code in int0e handler...
VOID disable_thread(IN PVOID  StartContext){
        PPTE pte;
        PPDE pde;
        PPTE_NOPAE pte_nopae;
        PPDE_NOPAE pde_nopae;
        PLINEAR_ADDRESS pLinear;
        PLINEAR_ADDRESS_PTE pLinearPte;
        PLINEAR_ADDRESS_NOPAE pLinear_nopae;
        PLINEAR_ADDRESS_PTE_NOPAE pLinearPte_nopae;
        ULONG      current, counter;
        NTSTATUS   status;
        PEPROCESS  eprocess;
wait:        
        KeWaitForSingleObject(&ma_thread_event, Executive, KernelMode, FALSE, 0);
        status = PsLookupProcessByProcessId(traced_pid, &eprocess);
        if (!NT_SUCCESS(status)){
                KeSetEvent(&int0e_event, IO_NO_INCREMENT, FALSE);
                goto wait;
        }
        
        KeAttachProcess(eprocess);
        __try{
                ProbeForRead((PVOID)start_range, end_range - start_range, 1);
                current = start_range;           
                counter = end_range - start_range;
                                
                pte = PTE_OFFSET;
                pde = PDE_OFFSET;        
                pte_nopae = PTE_OFFSET_NOPAE;
                pde_nopae = PDE_OFFSET_NOPAE;
                                
                while (counter){
                                 
                        __asm mov eax, current
                        __asm mov eax, [eax]    //pagein page...
                        pLinear = (PLINEAR_ADDRESS)&current;
                        pLinearPte = (PLINEAR_ADDRESS_PTE)&current;
                        pLinear_nopae = (PLINEAR_ADDRESS_NOPAE)&current;
                        pLinearPte_nopae = (PLINEAR_ADDRESS_PTE_NOPAE)&current;
                                        
                        if (b_pae)
                                pte[pLinearPte->Table].UserSupervisor = 1;
                        else
                                pte_nopae[pLinearPte_nopae->Table].UserSupervisor = 1;
                                                
                        __invlpg((PVOID)current);        
                                       
                        counter -= PAGE_SIZE;
                        current += PAGE_SIZE;                        
                }                
                
                KeDetachProcess();
                ObDereferenceObject(eprocess);
                KeSetEvent(&int0e_event, IO_NO_INCREMENT, FALSE);
                
                
        }__except(EXCEPTION_EXECUTE_HANDLER){
                KeDetachProcess();
                ObDereferenceObject(eprocess);
                KeSetEvent(&int0e_event, IO_NO_INCREMENT, FALSE);
        } 
        
        goto wait;        
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegPath){
        ULONG64         msr;
        ULONG           nx_state;
        ULONG           c_cr4;
        UNICODE_STRING  us_device, us_symlink;
        NTSTATUS        status; 
        PDEVICE_OBJECT  pDeviceObject;
        UCHAR           i;
        PETHREAD        cur_thread;
        PDEVICE_EXTENSION pExtension;
        HANDLE          thandle;
        
        c_cr4 = __readcr4();
        if (TestBit(c_cr4, 5))
                b_pae = TRUE;
        else
                b_pae = FALSE;
        
        RtlInitUnicodeString(&us_device, szDevice);
        RtlInitUnicodeString(&us_symlink, szSymlink);
        
        status = IoCreateDevice(pDriverObject,
                                sizeof(DEVICE_EXTENSION),
                                &us_device,
                                FILE_DEVICE_UNKNOWN,
                                0,
                                FALSE,
                                &pDeviceObject);
        
        if(status)
                return status;
        
        status = IoCreateSymbolicLink(&us_symlink, &us_device);
        if (status){
                IoDeleteDevice(pDeviceObject);
                return status;
        }
        
        PsCreateSystemThread(&thandle, THREAD_ALL_ACCESS, 0,0,0, disable_thread, 0);
        KeInitializeEvent(&ma_thread_event, SynchronizationEvent, FALSE);
        KeInitializeEvent(&int0e_event, SynchronizationEvent, FALSE);
        
        pDeviceObject->Flags |= DO_BUFFERED_IO;
        pExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
        pExtension->HandleCount = 0;
        
        KeInitializeSpinLock(&spin_lock);
        
        pDriverObject->MajorFunction[IRP_MJ_CREATE] =\
        pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
        pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ServiceHandle;
        //pDriverObject->DriverUnload = unloadme;
        
        cur_thread = PsGetCurrentThread();
        
        for (i = 0; i < KeNumberProcessors; i++){
                KeSetAffinityThread(cur_thread, 1 << i);
                HookInterupt((ULONG)new_int0e, 0xE, &old_int0es[i], &old_int0e);
        }
        return STATUS_SUCCESS;
}
