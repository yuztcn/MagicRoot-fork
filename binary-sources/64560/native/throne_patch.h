#ifndef MAGICROOT_THRONE_PATCH_H
#define MAGICROOT_THRONE_PATCH_H

#include <stddef.h>
#include <stdint.h>

/*
 * Replace track_throne's ksu_cred references with init_cred and append the
 * init_cred symbol for the normal per-profile symbol resolver.  Returns 0 on
 * success or an explicit non-fatal "absent" result, -1 on malformed input or
 * allocation failure.  Error text is written only for the latter cases.
 */
int patch_track_throne(uint8_t **pdata, size_t *plen, char *err, size_t errlen);

#endif
