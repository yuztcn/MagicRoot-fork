#!/system/bin/sh
# HOneClick g928 KASLR helper.
# Usage: grab_slide_618.sh <profile-dir>
set -u
B=${1:?profile dir required}
D=/data/local/tmp/honor
rm -rf "$D"
mkdir -p "$D" || exit 1
cp "$B/forker_618" "$D/forker" 2>/dev/null || exit 1
cp "$B/grab_honor.sh" "$D/grab.sh" 2>/dev/null || exit 1
chmod 755 "$D/forker" "$D/grab.sh" 2>/dev/null || true
cd "$D" || exit 1
sh ./grab.sh
GRAB_RC=$?
echo "KASLR_GRAB_RC=$GRAB_RC"
[ "$GRAB_RC" = "0" ] || exit "$GRAB_RC"
"$B/kaslr_slide" "$D"
