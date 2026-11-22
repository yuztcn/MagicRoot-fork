#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef int (*stp_void_fn)(void);

int main(void)
{
    const char *paths[] = {"/vendor/lib64/libstp.so", "libstp.so", NULL};
    void *h = NULL;
    for (int i = 0; paths[i]; i++) {
        h = dlopen(paths[i], RTLD_NOW | RTLD_GLOBAL);
        if (h) { fprintf(stderr, "loaded %s\n", paths[i]); break; }
        fprintf(stderr, "dlopen %s: %s\n", paths[i], dlerror());
    }
    if (!h) return 2;
    stp_void_fn clear = (stp_void_fn)dlsym(h, "StpClearStatus");
    stp_void_fn clean = (stp_void_fn)dlsym(h, "StpCleanKshieldStatus");
    fprintf(stderr, "clear=%p clean=%p\n", (void *)clear, (void *)clean);
    int rc1 = clear ? clear() : -999;
    int rc2 = clean ? clean() : -999;
    printf("StpClearStatus=%d StpCleanKshieldStatus=%d\n", rc1, rc2);
    fflush(stdout);
    return 0;
}
