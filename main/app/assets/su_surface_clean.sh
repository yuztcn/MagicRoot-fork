#!/system/bin/sh
# Danger: remove the su entry detection surface used by Honor hisecd
# [check-su].  Disables su_compat, removes MagicRoot's userdata wrappers and
# attempts to remove /system/bin/su.  Rootd is not touched.  KSU su may stop
# working until its manager reinstalls it or the device reboots.
set -u
D=/data/local/tmp/magic
LOG=$D/su-surface-clean.log
mkdir -p "$D" 2>/dev/null || true
: > "$LOG" 2>/dev/null || true

log() {
    printf '%s\n' "$*"
    printf '%s\n' "$*" >> "$LOG" 2>/dev/null || true
}

log "SU_SURFACE_CLEAN_BEGIN"

if [ -x /data/adb/ksud ]; then
    timeout 15 /data/adb/ksud feature set su_compat 0 >/dev/null 2>&1
    log "SUCOMPAT_DISABLE_RC=$?"
else
    log "SUCOMPAT_DISABLE_RC=ksud_missing"
fi

rm -f "$D/su" 2>/dev/null || true
if [ -e "$D/su" ]; then
    log "SAFE_SU=present"
else
    log "SAFE_SU=removed"
fi

if grep -q " $D/product_bin /product/bin " /proc/mounts 2>/dev/null; then
    umount /product/bin 2>/dev/null
    log "PRODUCT_BIN_UMOUNT_RC=$?"
else
    log "PRODUCT_BIN=mount_absent"
fi
rm -rf "$D/product_bin" 2>/dev/null || true

if [ -e /system/bin/su ] || [ -L /system/bin/su ]; then
    rm -f /system/bin/su 2>/dev/null || true
    if [ -e /system/bin/su ] || [ -L /system/bin/su ]; then
        log "SYSTEM_SU=present reason=remove_denied"
    else
        log "SYSTEM_SU=removed"
    fi
else
    log "SYSTEM_SU=absent"
fi

log "SU_SURFACE_CLEAN_DONE"
exit 0
