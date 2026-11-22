#!/system/bin/sh
# 1.0.33 g264：把 su_lkm 叠进 /system_ext/bin，供普通 App 使用
set -u
D=/data/local/tmp/magic
S=$D/su-g264
# Prefer the ksud extracted from the currently selected manager; the bundled
# g264 ksud remains the fallback when no manager component was staged.
K=${1:-$D/ksu6157-g264/ksud}
SUCOMPAT=${2:-1}
R=/data/local/tmp/route/m6

mkdir -p "$R" /data/adb/ksu/bin || exit 2

cp -f "$S/su_lkm" "$D/su_lkm" || exit 3
chmod 755 "$D/su_lkm"
cp -f "$S/su_overlay_helper" "$R/su_overlay_helper" || exit 4
cp -f "$S/su_optional.sh" "$R/su_optional.sh" || exit 5
cp -f "$S/su_lkm" "$R/su_forward" || exit 6
chmod 755 "$R/su_overlay_helper" "$R/su_forward" "$R/su_optional.sh"

[ -x "$K" ] || exit 7
cp -f "$K" /data/adb/ksud || exit 7
chmod 755 /data/adb/ksud
cp -f "$S/su_lkm" /data/adb/ksu/bin/su || exit 8
chmod 755 /data/adb/ksu/bin/su

if [ "$SUCOMPAT" = "0" ]; then
    NO_SUCOMPAT=1 sh "$R/su_optional.sh" enable
else
    sh "$R/su_optional.sh" enable
fi
_rc=$?
echo "SU_SETUP_RC=$_rc"
exit $_rc
