
#ifndef SEGMENTSFI_TRAMPOLINE_MODIFY_FUNCTION_CALL
#define SEGMENTSFI_TRAMPOLINE_MODIFY_FUNCTION_CALL(x) x
#endif

 .globl change_ds_and_invoke
.type change_ds_and_invoke,@function
.align 16
change_ds_and_invoke:
_change_ds_and_invoke:
    call get_curr_segment_sfi_context@PLT //retrieve curr switch context
    mov %eax, %ecx

    pop %eax                    // prev return in caller save reg
    mov %ebx      , 0x10(%ecx)  // save two callee save regs so we can use it
    mov %esi      , 0x14(%ecx)

    mov %ecx      , %ebx        // move ctx to callee save

    mov %eax      , 0xc(%ebx)   // save old return
    mov 0x8(%ebx) , %eax        // get func_ptr
    mov 0x0(%ebx) , %esi        // get app_domain
    mov 0x4(%ebx) , %ds         // switch to sandbox domain
    SEGMENTSFI_TRAMPOLINE_MODIFY_FUNCTION_CALL(call *%eax) // call sbx function

    mov %esi      , %ds         // switch to app domain
    mov 0xc(%ebx) , %ecx        // get old return

    push %ecx                   // restore the stack

    mov 0x14(%ebx), %esi        // restore esi callee save
    mov 0x10(%ebx), %ebx        // restore ebx callee save

    ret

#undef SEGMENTSFI_TRAMPOLINE_MODIFY_FUNCTION_CALL
