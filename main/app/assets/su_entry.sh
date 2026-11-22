#!/system/bin/sh
# su entry for KernelSU-family LKMs.
#
# Reference: legacy root_stage v1.6:
#   - v1.6 relies on the kernel su_compat hooks (no real su file on disk)
#   - it patches the Termux su wrapper search list to include /system_ext/bin/su
#
# This script does not install a real su binary.  /system/bin/su is resolved
# by the in-kernel sucompat hook to the authorized ksud userspace.
set -u
D=/data/local/tmp/magic
ADB=/data/adb
TS=/data/data/com.termux/files/usr/bin/su
PATH=/data/adb/ksu/bin:/system/bin:/system/xbin:/system_ext/bin
export PATH

echo "SU_ENTRY_BEGIN"
[ "$(id -u 2>/dev/null || echo 1)" = "0" ] || {
    echo "SU_ENTRY_FAIL=not_root"
    exit 1
}

# The kernel hook needs a usable ksud target.
if [ ! -x "$ADB/ksud" ]; then
    echo "SU_ENTRY_FAIL=ksud_missing"
    exit 2
fi

# No real su file: keep it that way (PMX v1.6 behavior).
if [ -e /system/bin/su ] || [ -L /system/bin/su ]; then
    echo "SU_ENTRY_REAL_SU=$(ls -l /system/bin/su 2>/dev/null | tr '\n' ' ')"
else
    echo "SU_ENTRY_REAL_SU=absent"
fi

# Use a userdata-only "safe" su path.  hisecd [check-su] only scans
# /sbin,/system/bin,/vendor/bin,/odm/bin,/system/vendor/bin, so keeping our
# wrapper under /data/local/tmp avoids adding another detected su path.
SAFE_SU=$D/su
ROOTD_CLIENT=${1:-${MAGICROOT_SU:-$D/pc98260-su}}
if [ ! -x "$ROOTD_CLIENT" ] && [ -x "$D/98260-g264/pc98260-su" ]; then
    ROOTD_CLIENT=$D/98260-g264/pc98260-su
fi
if [ ! -x "$ROOTD_CLIENT" ] && [ -x "$D/98260/pc98260-su" ]; then
    ROOTD_CLIENT=$D/98260/pc98260-su
fi
if [ -x "$ROOTD_CLIENT" ]; then
    if [ -n "${MAGICROOT_SU_SOCK:-}" ]; then
        printf '#!/system/bin/sh\nexec env PC98260_SOCK=%s %s "$@"\n' \
            "$MAGICROOT_SU_SOCK" "$ROOTD_CLIENT" > "$SAFE_SU"
    else
        printf '#!/system/bin/sh\nexec %s "$@"\n' "$ROOTD_CLIENT" > "$SAFE_SU"
    fi
    chmod 755 "$SAFE_SU" 2>/dev/null || true
    echo "SU_ENTRY_SAFE_SU=$SAFE_SU client=$ROOTD_CLIENT"
else
    echo "SU_ENTRY_SAFE_SU=absent reason=rootd_client_missing client=$ROOTD_CLIENT"
fi

# /product/bin/su used to be a bind-mounted wrapper so every app could find
# su.  Duck Detector sees it as a real SU artifact, and it is not needed for
# KSU-authorized apps.  Keep the old mount removable, but never create it by
# default; it is a deliberate detection surface.
if grep -q " $D/product_bin /product/bin " /proc/mounts 2>/dev/null; then
    if umount /product/bin 2>/dev/null; then
        echo "SU_ENTRY_PRODUCT_BIN=unmounted_old_mount"
    else
        echo "SU_ENTRY_PRODUCT_BIN=old_mount_busy"
    fi
fi
if [ "${MAGICROOT_SU_ENTRY_PRODUCT_BIN:-0}" = "1" ]; then
    PRODUCT_BIN=/product/bin
    PRODUCT_STAGE=$D/product_bin
    if [ -x "$ROOTD_CLIENT" ] && [ -d "$PRODUCT_BIN" ] && ! grep -q " $PRODUCT_BIN " /proc/mounts 2>/dev/null; then
        rm -rf "$PRODUCT_STAGE"
        if cp -a "$PRODUCT_BIN" "$PRODUCT_STAGE" 2>/dev/null; then
            if [ -x "$D/su_forward" ]; then
                cp "$D/su_forward" "$PRODUCT_STAGE/su" 2>/dev/null || true
            fi
            if [ -x "$D/su_forward" ]; then
                chmod 755 "$PRODUCT_STAGE/su" 2>/dev/null || true
                chcon u:object_r:system_file:s0 "$PRODUCT_STAGE/su" 2>/dev/null || true
                if mount --bind "$PRODUCT_STAGE" "$PRODUCT_BIN"; then
                    echo "SU_ENTRY_PRODUCT_BIN=$PRODUCT_BIN/su"
                else
                    echo "SU_ENTRY_PRODUCT_BIN=failed_mount"
                fi
            else
                echo "SU_ENTRY_PRODUCT_BIN=skipped reason=no_su_forward"
            fi
        else
            echo "SU_ENTRY_PRODUCT_BIN=failed_copy"
        fi
    else
        echo "SU_ENTRY_PRODUCT_BIN=skip mounted_or_no_rootd"
    fi
else
    echo "SU_ENTRY_PRODUCT_BIN=disabled reason=detection_surface"
fi

# PMX v1.6 su entry logic: patch Termux's wrapper search list.  Prefer the
# safe rootd wrapper path; legacy locations are kept last only as fallbacks.
if [ -f "$TS" ]; then
    if grep -q '/product/bin/su' "$TS" 2>/dev/null || ! grep -q '/data/local/tmp/magic/su' "$TS" 2>/dev/null; then
        cp -p "$TS" "$TS.magicroot.bak" 2>/dev/null || true
        awk '
        /^for p in / {
            print "for p in /data/adb/ksu/bin/su /data/local/tmp/magic/su /system_ext/bin/su /debug_ramdisk/su /system/sbin/su /system/xbin/su /su/bin/su /magisk/.core/bin/su /sbin/su /system/bin/su /vendor/bin/su /odm/bin/su /system/vendor/bin/su";
            next;
        }
        { print }
        ' "$TS" > "$TS.magicroot.tmp" 2>/dev/null || true
        if [ -s "$TS.magicroot.tmp" ] &&
           cat "$TS.magicroot.tmp" > "$TS" 2>/dev/null; then
            rm -f "$TS.magicroot.tmp"
            echo "SU_ENTRY_TERMUX=patched mode=safe-path"
        else
            rm -f "$TS.magicroot.tmp"
            echo "SU_ENTRY_TERMUX=patch_failed"
        fi
    fi
    echo "SU_ENTRY_TERMUX_LINE=$(grep -n 'for p in' "$TS" 2>/dev/null | head -1)"
else
    echo "SU_ENTRY_TERMUX=not_installed"
fi

# su_entry is intentionally independent from the su_compat feature.
# Prefer the traditional path when present, otherwise use the real ksud
# binary under /data/adb (requires this script to run as root/rootd).
SU_BIN=""
# Prefer the real KSU sucompat entry when available; the rootd wrapper is
# a fallback and may be unreachable from a KSU SELinux context after late-load.
if [ -x /data/adb/ksu/bin/su ]; then
    SU_BIN=/data/adb/ksu/bin/su
elif [ -x /system/bin/su ]; then
    SU_BIN=/system/bin/su
elif [ -x "$SAFE_SU" ]; then
    SU_BIN="$SAFE_SU"
fi
echo "SU_ENTRY_BACKEND=${SU_BIN:-none}"
if [ -z "$SU_BIN" ]; then
    echo "SU_ENTRY_FAIL=no_su_path"
    exit 1
fi
SU_UID=$(timeout 8 "$SU_BIN" -c 'id -u' 2>/dev/null | tr -d '\r\n')
case "$SU_UID" in
    0) echo "SU_ENTRY=ok backend=$SU_BIN uid=0" ; exit 0 ;;
    '') echo "SU_ENTRY=failed backend=$SU_BIN uid=unknown" ; exit 1 ;;
    *) echo "SU_ENTRY=failed backend=$SU_BIN uid=$SU_UID" ; exit 1 ;;
esac
