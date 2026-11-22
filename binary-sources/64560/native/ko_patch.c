/*
 * ko_patch.c —— 在手机上为当前 boot 打 KernelSU 模块。
 *
 *   ko_patch <in.ko> <out.ko> <syms.txt> <slide_hex> <kernel_release>
 *
 * syms.txt 每行: <name> 0x<link_addr>；运行时地址 = link_addr + slide。
 * 所有 SHN_UNDEF 且能在 syms.txt 找到的符号 -> SHN_ABS + 绝对地址。
 * vermagic = <kernel_release> + " SMP preempt mod_unload modversions aarch64"。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "throne_patch.h"

#define SHN_ABS 0xFFF1

struct sec {
    uint32_t name_off, type, link;
    uint64_t flags, addr, off, size, align, entsize;
};

static uint8_t *read_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

static const char *cstr(const uint8_t *blob, size_t len, uint32_t off)
{
    if (off >= len) return "";
    return (const char *)(blob + off);
}

static int section_name_cmp(const uint8_t *shstr, size_t shstr_len,
                            const struct sec *s, const char *want)
{
    return strcmp(cstr(shstr, shstr_len, s->name_off), want) == 0;
}

/* 返回 0 成功 */
static int syms_has_init_cred(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int found = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        char name[256];
        if (sscanf(line, "%255s", name) == 1 && strcmp(name, "init_cred") == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int patch_symbols(uint8_t *data, size_t len, const char *syms_path,
                         const char *kallsyms_path, uint64_t slide,
                         int *patched_out, int *missing_out,
                         int *repaired_out)
{
    uint64_t e_shoff = *(uint64_t *)(data + 0x28);
    uint16_t e_shentsize = *(uint16_t *)(data + 0x3a);
    uint16_t e_shnum = *(uint16_t *)(data + 0x3c);
    uint16_t e_shstrndx = *(uint16_t *)(data + 0x3e);
    if (e_shoff + (uint64_t)e_shnum * e_shentsize > len) return -1;

    struct sec *secs = calloc(e_shnum, sizeof(*secs));
    for (int i = 0; i < e_shnum; i++) {
        uint8_t *p = data + e_shoff + (uint64_t)i * e_shentsize;
        secs[i].name_off = *(uint32_t *)(p + 0);
        secs[i].type = *(uint32_t *)(p + 4);
        secs[i].flags = *(uint64_t *)(p + 8);
        secs[i].addr = *(uint64_t *)(p + 16);
        secs[i].off = *(uint64_t *)(p + 24);
        secs[i].size = *(uint64_t *)(p + 32);
        secs[i].link = *(uint32_t *)(p + 40);
        secs[i].align = *(uint64_t *)(p + 48);
        secs[i].entsize = *(uint64_t *)(p + 56);
    }
    struct sec *shstr = &secs[e_shstrndx];
    const uint8_t *shstr_data = data + shstr->off;

    struct sec *symtab = NULL;
    int modinfo_idx = -1;
    for (int i = 0; i < e_shnum; i++) {
        if (section_name_cmp(shstr_data, shstr->size, &secs[i], ".symtab")) { symtab = &secs[i]; break; }
    }
    for (int i = 0; i < e_shnum; i++)
        if (section_name_cmp(shstr_data, shstr->size, &secs[i], ".modinfo")) { modinfo_idx = i; break; }
    if (!symtab) { free(secs); return -1; }

    struct sec *strtab = &secs[symtab->link];
    const uint8_t *str_data = data + strtab->off;
    size_t entsize = symtab->entsize ? symtab->entsize : 24;
    size_t count = symtab->size / entsize;

    FILE *sf = fopen(syms_path, "r");
    if (!sf) { free(secs); return -1; }
    char line[512];
    int patched = 0, missing = 0, repaired = 0;
    /* KernelSU/manager LKMs may carry SHN_XINDEX (0xffff) in st_shndx.
       Upstream repairs those to the .modinfo section index before loading;
       otherwise the module loader rejects the section table. */
    if (modinfo_idx >= 0) {
        for (size_t i = 1; i < count; i++) {
            uint8_t *e = data + symtab->off + i * entsize;
            uint16_t shndx = *(uint16_t *)(e + 6);
            if (shndx == 0xffff) {
                *(uint16_t *)(e + 6) = (uint16_t)modinfo_idx;
                repaired++;
            }
        }
    }
    while (fgets(line, sizeof line, sf)) {
        char name[256];
        unsigned long long link;
        if (sscanf(line, "%255s %llx", name, &link) != 2) continue;
        uint64_t addr = link + slide;
        for (size_t i = 1; i < count; i++) {
            uint8_t *e = data + symtab->off + i * entsize;
            uint16_t shndx = *(uint16_t *)(e + 6);
            if (shndx != 0) continue;
            const char *sn = cstr(str_data, strtab->size, *(uint32_t *)e);
            if (strcmp(sn, name) != 0) continue;
            *(uint16_t *)(e + 6) = SHN_ABS;
            *(uint64_t *)(e + 8) = addr;
            patched++;
            break;
        }
    }
    fclose(sf);

    /* Optional runtime resolver.  A manager update can add symbol references
       that the shipped per-profile table does not know yet.  /proc/kallsyms
       (dumped by the runner through the already-rooted rootd client) carries
       the runtime address; subtract the measured slide to recover the
       link-time value this tool expects.  Exact name match only; anything
       else stays missing and the caller keeps failing closed. */
    if (kallsyms_path && kallsyms_path[0]) {
        FILE *kf = fopen(kallsyms_path, "r");
        if (kf) {
            for (size_t i = 1; i < count; i++) {
                uint8_t *e = data + symtab->off + i * entsize;
                if (*(uint16_t *)(e + 6) != 0 || *(uint32_t *)e == 0) continue;
                const char *sn = cstr(str_data, strtab->size, *(uint32_t *)e);
                if (!sn || !sn[0]) continue;
                char kline[512];
                int found = 0;
                uint64_t val = 0;
                rewind(kf);
                while (fgets(kline, sizeof kline, kf)) {
                    unsigned long long a = 0;
                    char type = 0, kn[256];
                    if (sscanf(kline, "%llx %c %255s", &a, &type, kn) != 3) continue;
                    if (strcmp(kn, sn) != 0) continue;
                    /* A hidden kallsyms address (kptr_restrict) is not an
                       address; refuse it instead of writing ABS=0. */
                    if (a == 0) continue;
                    /* /proc/kallsyms already carries the runtime address, and
                       an ABS symbol must hold exactly that.  Do not add or
                       subtract the slide here. */
                    val = (uint64_t)a;
                    found = 1;
                    break;
                }
                if (!found) continue;
                *(uint16_t *)(e + 6) = SHN_ABS;
                *(uint64_t *)(e + 8) = val;
                patched++;
                printf("KALLSYMS_FALLBACK=%s=0x%llx\n", sn, (unsigned long long)val);
            }
            fclose(kf);
        }
    }

    /* 统计仍未定义的符号；名字用于运行时补符号诊断 */
    for (size_t i = 1; i < count; i++) {
        uint8_t *e = data + symtab->off + i * entsize;
        if (*(uint16_t *)(e + 6) == 0 && *(uint32_t *)e != 0) {
            const char *sn = cstr(str_data, strtab->size, *(uint32_t *)e);
            missing++;
            if (sn && sn[0]) printf("MISSING_SYM=%s\n", sn);
        }
    }
    *patched_out = patched;
    *missing_out = missing;
    *repaired_out = repaired;
    free(secs);
    return 0;
}

static uint8_t *patch_vermagic(uint8_t *data, size_t *len, const char *magic)
{
    uint64_t e_shoff = *(uint64_t *)(data + 0x28);
    uint16_t e_shentsize = *(uint16_t *)(data + 0x3a);
    uint16_t e_shnum = *(uint16_t *)(data + 0x3c);
    uint16_t e_shstrndx = *(uint16_t *)(data + 0x3e);
    struct sec *secs = calloc(e_shnum, sizeof(*secs));
    for (int i = 0; i < e_shnum; i++) {
        uint8_t *p = data + e_shoff + (uint64_t)i * e_shentsize;
        secs[i].name_off = *(uint32_t *)(p + 0);
        secs[i].off = *(uint64_t *)(p + 24);
        secs[i].size = *(uint64_t *)(p + 32);
    }
    const uint8_t *shstr_data = data + secs[e_shstrndx].off;
    size_t shstr_size = secs[e_shstrndx].size;
    int idx = -1;
    for (int i = 0; i < e_shnum; i++)
        if (section_name_cmp(shstr_data, shstr_size, &secs[i], ".modinfo")) { idx = i; break; }
    if (idx < 0) { free(secs); return NULL; }

    size_t old_off = secs[idx].off, old_size = secs[idx].size;
    size_t magic_len = strlen(magic);
    size_t new_size = old_size + 10 + magic_len + 1; /* "vermagic=" + magic + NUL */
    uint8_t *blob = malloc(new_size);
    memcpy(blob, data + old_off, old_size);
    /* 旧 vermagic= -> zermagic= */
    for (size_t i = 0; i + 9 <= old_size; i++) {
        if (memcmp(blob + i, "vermagic=", 9) == 0)
            memcpy(blob + i, "zermagic=", 9);
    }
    memcpy(blob + old_size, "vermagic=", 9);
    memcpy(blob + old_size + 9, magic, magic_len);
    blob[old_size + 9 + magic_len] = 0;

    size_t new_off = *len;
    uint8_t *grown = realloc(data, *len + new_size);
    if (!grown) { free(blob); free(secs); return NULL; }
    data = grown;
    memcpy(data + new_off, blob, new_size);
    *len += new_size;

    uint8_t *hdr = data + e_shoff + (uint64_t)idx * e_shentsize;
    *(uint64_t *)(hdr + 24) = new_off;
    *(uint64_t *)(hdr + 32) = new_size;
    free(blob);
    free(secs);
    return data;
}

int main(int argc, char **argv)
{
    if (argc != 6 && argc != 7) {
        fprintf(stderr, "usage: %s <in.ko> <out.ko> <syms.txt> <slide_hex> <vermagic> [kallsyms.txt]\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    uint8_t *data = read_all(argv[1], &len);
    if (!data) { printf("ERR=read:%d\n", errno); return 1; }
    uint64_t slide = strtoull(argv[4], NULL, 0);
    char throne_err[64] = {0};
    const char *throne_env = getenv("MAGICROOT_THRONE_PATCH");
    /* Default stays ON: this is the behavior of the build verified against
     * official KernelSU 3.3.1 (MISSING=0, TRACK_THRONE=patched, manager
     * registers and su works).  The env opt-out exists so a kernel where the
     * module's own ksu_cred path is correct can be tested without the
     * init_cred rewrite. */
    int want_throne = 1;
    if (throne_env &&
        (!strcmp(throne_env, "0") || !strcmp(throne_env, "off") ||
         !strcmp(throne_env, "false") || !strcmp(throne_env, "no")))
        want_throne = 0;
    if (!want_throne) {
        printf("TRACK_THRONE=disabled\n");
    } else if (!syms_has_init_cred(argv[3])) {
        /* An unproven address is never guessed.  Preserve the legacy module
         * and let the runner report INIT_CRED=unavailable explicitly. */
        printf("TRACK_THRONE=unavailable\n");
    } else if (patch_track_throne(&data, &len, throne_err, sizeof throne_err) != 0) {
        printf("ERR=track_throne:%s\n", throne_err);
        free(data);
        return 1;
    }

    int patched = 0, missing = 0, repaired = 0;
    if (patch_symbols(data, len, argv[3], argc > 6 ? argv[6] : NULL, slide,
                      &patched, &missing, &repaired) != 0) {
        printf("ERR=symbols\n");
        return 1;
    }
    char vermagic[512];
    snprintf(vermagic, sizeof vermagic,
             "%s SMP preempt mod_unload modversions aarch64", argv[5]);
    data = patch_vermagic(data, &len, vermagic);
    if (!data) {
        printf("ERR=vermagic\n");
        return 1;
    }
    FILE *out = fopen(argv[2], "wb");
    if (!out) { printf("ERR=write:%d\n", errno); return 1; }
    fwrite(data, 1, len, out);
    fclose(out);
    free(data);
    printf("PATCHED=%d MISSING=%d REPAIRED=%d VERMAGIC=%s\n", patched, missing, repaired, vermagic);
    return 0;
}
