#ifndef MAGICROOT_FUTEX_SYNC_H
#define MAGICROOT_FUTEX_SYNC_H

#include <stdint.h>

/* Shared by cred_target (publisher) and wait_helper (waiter).
 * `seq` is the futex word; `event` is the value guarded by it. */
enum futex_sync_event {
    FUTEX_EV_NONE = 0,
    FUTEX_EV_CRED = 1,
    FUTEX_EV_MODULE = 2,
    FUTEX_EV_MODULE_SKIP = 3,
    FUTEX_EV_FAIL = 4,
};

struct futex_sync {
    volatile uint32_t seq;
    volatile int32_t event;
    volatile int32_t bit16;
    volatile int32_t pid;
    volatile uint64_t cred;
};

#endif
