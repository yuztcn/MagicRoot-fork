/* g2646292297b1 6.1.157 AMG-AN00, BTF/kallsyms derived */
#ifndef OFFSETS_H
#define OFFSETS_H
#define TIMER_LINK     UINT64_C(0xffffffc0803bed18)  /* do_timer_create + 0x94 */
#define CRED_LINK      UINT64_C(0xffffffc0800e6c6c)  /* prepare_creds + 0x20 */
#define SELINUX_LINK   UINT64_C(0xffffffc0826fca00)  /* selinux_state */
#define LINK_USER_NS   UINT64_C(0xffffffc0820d0748)  /* init_user_ns */
#define LINK_ROOT_USER UINT64_C(0xffffffc0820d09d8)  /* root_user */
#define LINK_GROUPS    UINT64_C(0xffffffc0820d1cf8)  /* init_groups */
#define LINK_UCOUNTS   UINT64_C(0xffffffc0820d2268)  /* init_ucounts */
#endif
