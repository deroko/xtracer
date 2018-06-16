#include        "defs.h"

extern ULONG old_int0e;
extern ULONG ActiveCr3;

void __declspec(naked) ClearWP(void){
        __asm{
                cli
                push    eax
                mov     eax, cr0
                and     eax, 0FFFEFFFFh
                mov     cr0, eax
                pop     eax
                retn
        }
}

void __declspec(naked) SetWP(void){
        __asm{
                push    eax
                mov     eax, cr0
                or      eax, 10000h
                mov     cr0, eax
                pop     eax
                sti
                retn
        }
}

void __declspec(naked) new_int0e(void){
        __asm{
                cli
                pushad
                push    fs
                push    ds
                push    es
                mov     ax, 30h
                mov     fs, ax
                mov     ax, 23h
                mov     ds, ax
                mov     es, ax
                mov     eax, cr2
                push    eax
                
                mov     eax, cr3
                cmp     cs:ActiveCr3, eax
                jne     __old_handler
                mov     eax, [esp.regErrorCode]
                bt      eax, 2                  //user or supervisor
                jnb     __old_handler
                
                mov     eax, esp
                push    eax
                call    HandleAccessViolation
                cli
                test    al, al
                jnz     __exit_exception                


__old_handler:  pop     eax
                mov     cr2, eax
                pop     es
                pop     ds
                pop     fs
                popad
                jmp     cs:[old_int0e]

__exit_exception:
                pop     eax
                mov     cr2, eax
                pop     es
                pop     ds
                pop     fs
                popad
                add     esp, 4
                iretd
        }       
}
        
