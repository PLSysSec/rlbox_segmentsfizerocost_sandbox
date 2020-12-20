 .globl change_ds_and_invoke
.type change_ds_and_invoke,@function
.align 16
change_ds_and_invoke:
_change_ds_and_invoke:
    pop %eax                    // prev return in caller save reg
    pop %ecx                    // ctx in caller save reg
    mov %ebx      , 0x18(%ecx)  // save two callee save regs so we can use it
    mov %esi      , 0x1c(%ecx)

    mov %ecx      , %ebx        // move ctx to callee save

    mov %eax      , 0x14(%ebx)  // save old return
    mov 0xc(%ebx) , %eax        // get func_ptr
    mov 0x0(%ebx) , %esi        // get app_domain
    mov 0x8(%ebx) , %ds         // switch to sbx data domain
    lcall *%eax                // call sbx function and switch to sbx code domani

    mov %esi      , %ds         // switch to app data domain
    mov 0x4(%ebx) , %cs         // switch to app code domain
    mov 0x14(%ebx), %ecx        // get old return

    push %ebx                   // restore the stack
    push %ecx

    mov 0x1c(%ebx), %esi        // restore esi callee save
    mov 0x18(%ebx), %ebx        // restore ebx callee save

    ret
