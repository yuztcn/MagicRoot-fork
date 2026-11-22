#!/system/bin/sh
set -eu
D="${1:-${HONOR_WORK:-/data/local/tmp/honor}}"
mkdir -p /data/adb/ksu/bin /data/adb/modules
# Atomic replace: a partial copy of ksud would leave the manager with a
# truncated binary until reboot.
if cp "$D/ksud" /data/adb/ksud.tmp.$$ 2>/dev/null; then
    chmod 755 /data/adb/ksud.tmp.$$ 2>/dev/null || true
    mv -f /data/adb/ksud.tmp.$$ /data/adb/ksud
else
    rm -f /data/adb/ksud.tmp.$$ 2>/dev/null || true
    cp "$D/ksud" /data/adb/ksud
    chmod 755 /data/adb/ksud
fi
# Manager-adaptive userspace: libksud may need its bundled libadbroot and the
# explicit data path.  Older/official ksud ignores the extra flags.
install_ok=0
if [ -f "$D/libadbroot.so" ]; then
    export LD_LIBRARY_PATH="$D"
    if /data/adb/ksud install --libadbroot "$D/libadbroot.so" --data-path /data/adb; then
        install_ok=1
    elif /data/adb/ksud install --data-path /data/adb; then
        install_ok=1
    elif /data/adb/ksud install; then
        install_ok=1
    fi
else
    if /data/adb/ksud install --data-path /data/adb; then
        install_ok=1
    elif /data/adb/ksud install; then
        install_ok=1
    fi
fi
[ "$install_ok" = "1" ] || echo "H1C_MANAGER_INSTALL=warn rc=all_failed"
ln -sf /data/adb/ksud /data/adb/ksu/bin/su
ln -sf /data/adb/ksud /data/adb/ksu/bin/ksud
SC=${MAGICROOT_SU_COMPAT:-1}
feature_set_h1c() {
    _name="$1"
    _value="$2"
    if /data/adb/ksud feature set "$_name" "$_value"; then
        echo "H1C_FEATURE_${_name}=${_value} rc=0"
    else
        echo "H1C_FEATURE_${_name}=${_value} rc=warn"
    fi
}
feature_set_h1c su_compat "$SC"
feature_set_h1c kernel_umount "${MAGICROOT_KERNEL_UMOUNT:-1}"
feature_set_h1c selinux_hide "${MAGICROOT_SELINUX_HIDE:-1}"
feature_set_h1c adb_root "${MAGICROOT_ADB_ROOT:-0}"
if [ "${MAGICROOT_ADB_ROOT:-0}" = "1" ]; then
    setprop ctl.restart adbd >/dev/null 2>&1 || true
    echo "H1C_ADB_ROOT=1 adbd_restart=requested"
fi
if [ "${MAGICROOT_SU_ENTRY:-0}" = "1" ] && [ -f "$D/su_entry.sh" ]; then
    if MAGICROOT_SU="${MAGICROOT_H1C_CLIENT:-}" \
       MAGICROOT_SU_SOCK="${MAGICROOT_H1C_SOCK:-}" \
       sh "$D/su_entry.sh"; then
        echo "H1C_SU_ENTRY=ok"
    else
        echo "H1C_SU_ENTRY=warn"
    fi
fi
/data/adb/ksud debug mark refresh || true
rm -f "$D/root_id" 2>/dev/null || true
id > "$D/root_id" 2>&1
grep -q 'uid=0(root)' "$D/root_id" 2>/dev/null ||
    { echo "ROOT_STAGE_FAIL=not_root"; exit 20; }
chmod 644 "$D/root_id" 2>/dev/null || true
echo ROOT_STAGE_OK
