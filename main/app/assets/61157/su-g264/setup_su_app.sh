#!/system/bin/sh
# 1.0.33 g264：把 su_lkm 叠进 /system_ext/bin，供普通 App 使用
set -u
D=${1:-/data/local/tmp/magic/61157}
S=$D/su-g264
K=${2:-$D/ksud}
R=/data/local/tmp/route/m6

mkdir -p "$R" /data/adb/ksu/bin || exit 2

cp -f "$S/su_lkm" "$D/su_lkm" || exit 3
chmod 755 "$D/su_lkm"
cp -f "$S/su_overlay_helper" "$R/su_overlay_helper" || exit 4
cp -f "$S/su_optional.sh" "$R/su_optional.sh" || exit 5
cp -f "$S/su_lkm" "$R/su_forward" || exit 6
chmod 755 "$R/su_overlay_helper" "$R/su_forward" "$R/su_optional.sh"

cp -f "$K" /data/adb/ksud || exit 7
chmod 755 /data/adb/ksud
cp -f "$S/su_lkm" /data/adb/ksu/bin/su || exit 8
chmod 755 /data/adb/ksu/bin/su

sh "$R/su_optional.sh" enable
_rc=$?
echo "SU_SETUP_RC=$_rc"
exit $_rc
