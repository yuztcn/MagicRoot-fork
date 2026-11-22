.arch armv8.5-a

.section .text,"ax",@progbits

.global override_creds
.type override_creds, %function
override_creds:
    bti c
    mrs x8, SP_EL0
    ldr x9, [x8, #0x908]
    add x8, x8, #0x908
    stlr x0, [x8]
    mov x0, x9
    ret
.size override_creds, . - override_creds

.global revert_creds
.type revert_creds, %function
revert_creds:
    bti c
    mrs x8, SP_EL0
    ldr x9, [x8, #0x908]
    add x8, x8, #0x908
    stlr x0, [x8]
    mov x0, x9
    ret
.size revert_creds, . - revert_creds

.global __get_task_comm
.type __get_task_comm, %function
__get_task_comm:
    paciasp
    stp x19, x30, [sp, #-16]!
    mov x19, x0
    mov x3, x1
    add x1, x2, #0x918
    mov x2, x3
    bl sized_strscpy
    mov x0, x19
    ldp x19, x30, [sp], #16
    autiasp
    ret
.size __get_task_comm, . - __get_task_comm

.global ebitmap_cmp
.type ebitmap_cmp, %function
ebitmap_cmp:
    bti c
    b ebitmap_equal
.size ebitmap_cmp, . - ebitmap_cmp

.global krealloc_noprof
.type krealloc_noprof, %function
krealloc_noprof:
    bti c
    mov w3, w2
    mov w4, #-1
    mov x2, #1
    b krealloc_node_align_noprof
.size krealloc_noprof, . - krealloc_noprof

.global kvrealloc_noprof
.type kvrealloc_noprof, %function
kvrealloc_noprof:
    bti c
    mov w3, w2
    mov w4, #-1
    mov x2, #1
    b kvrealloc_node_align_noprof
.size kvrealloc_noprof, . - kvrealloc_noprof

// This g186 tracepoint implementation uses RCU in tracepoint_probe_unregister.
// The caller immediately executes synchronize_rcu after this obsolete SRCU wait.
.global synchronize_srcu
.type synchronize_srcu, %function
synchronize_srcu:
    bti c
    ret
.size synchronize_srcu, . - synchronize_srcu

.section .bss.tracepoint_srcu,"aw",@nobits
.balign 8
.global tracepoint_srcu
.type tracepoint_srcu, %object
tracepoint_srcu:
    .zero 24
.size tracepoint_srcu, . - tracepoint_srcu

.section .modinfo,"a",@progbits
.asciz "brm_compat=honor-6.18.21-ge186-v1"

.section .note.GNU-stack,"",@progbits
